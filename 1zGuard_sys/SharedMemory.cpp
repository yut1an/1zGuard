#include "SharedMemory.h"

extern GLOBAL_STATE g_State;

NTSTATUS InitializeSharedMemory(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_State.SharedMemoryBase)
        return STATUS_SUCCESS;

    g_State.SharedMemorySectionObject = nullptr;

    NTSTATUS status;
    UNICODE_STRING sectionName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\1zGuardSharedMemory");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &sectionName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    LARGE_INTEGER maxSize;
    maxSize.QuadPart = sizeof(SHARED_MEMORY);

    status = ZwCreateSection(&g_State.SharedMemorySectionHandle,
                             SECTION_ALL_ACCESS,
                             &oa,
                             &maxSize,
                             PAGE_READWRITE,
                             SEC_COMMIT,
                             nullptr);
    if (!NT_SUCCESS(status))
        return status;

    status = ObReferenceObjectByHandle(
        g_State.SharedMemorySectionHandle,
        SECTION_MAP_READ | SECTION_MAP_WRITE,
        nullptr,
        KernelMode,
        &g_State.SharedMemorySectionObject,
        nullptr);
    if (!NT_SUCCESS(status)) {
        ZwClose(g_State.SharedMemorySectionHandle);
        g_State.SharedMemorySectionHandle = nullptr;
        return status;
    }

    SIZE_T viewSize = sizeof(SHARED_MEMORY);
    PVOID base = nullptr;
    status = MmMapViewInSystemSpace(g_State.SharedMemorySectionObject, &base, &viewSize);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(g_State.SharedMemorySectionObject);
        g_State.SharedMemorySectionObject = nullptr;
        ZwClose(g_State.SharedMemorySectionHandle);
        g_State.SharedMemorySectionHandle = nullptr;
        return status;
    }

    g_State.SharedMemoryBase = base;
    g_State.SharedMemorySize = viewSize;

    RtlZeroMemory(base, sizeof(SHARED_MEMORY));

    UNICODE_STRING eventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\1zGuardNewRequestEvent");
    InitializeObjectAttributes(&oa, &eventName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    status = ZwCreateEvent(&g_State.NewRequestEventHandle,
                           EVENT_MODIFY_STATE | SYNCHRONIZE,
                           &oa,
                           NotificationEvent,
                           FALSE);
    if (!NT_SUCCESS(status)) {
        MmUnmapViewInSystemSpace(g_State.SharedMemoryBase);
        g_State.SharedMemoryBase = nullptr;
        g_State.SharedMemorySize = 0;

        if (g_State.SharedMemorySectionObject) {
            ObDereferenceObject(g_State.SharedMemorySectionObject);
            g_State.SharedMemorySectionObject = nullptr;
        }
        ZwClose(g_State.SharedMemorySectionHandle);
        g_State.SharedMemorySectionHandle = nullptr;
        return status;
    }

    return STATUS_SUCCESS;
}

VOID UninitializeSharedMemory()
{
    if (g_State.SharedMemoryBase) {
        MmUnmapViewInSystemSpace(g_State.SharedMemoryBase);
        g_State.SharedMemoryBase = nullptr;
        g_State.SharedMemorySize = 0;
    }

    if (g_State.SharedMemorySectionObject) {
        ObDereferenceObject(g_State.SharedMemorySectionObject);
        g_State.SharedMemorySectionObject = nullptr;
    }

    if (g_State.SharedMemorySectionHandle) {
        ZwClose(g_State.SharedMemorySectionHandle);
        g_State.SharedMemorySectionHandle = nullptr;
    }

    if (g_State.NewRequestEventHandle) {
        ZwClose(g_State.NewRequestEventHandle);
        g_State.NewRequestEventHandle = nullptr;
    }
}

static VOID CopyUnicodeToBuffer(_In_opt_ PCUNICODE_STRING src, _Out_writes_(maxChars) PWCHAR dest, SIZE_T maxChars)
{
    if (!dest || maxChars == 0) return;

    dest[0] = L'\0';
    if (!src || !src->Buffer || src->Length == 0)
        return;

    PCWSTR buffer = src->Buffer;
    SIZE_T charsToCopy = src->Length / sizeof(WCHAR);
    if (charsToCopy >= 2 && buffer[0] == L'"' && buffer[charsToCopy - 1] == L'"') {
        buffer++;
        charsToCopy -= 2;
    }
    if (charsToCopy >= maxChars)
        charsToCopy = maxChars - 1;

    RtlCopyMemory(dest, buffer, charsToCopy * sizeof(WCHAR));
    dest[charsToCopy] = L'\0';
}

static BOOLEAN RemoveAskQueueNodeByRequestId(_In_ UINT32 requestId)
{
    BOOLEAN removed = FALSE;
    KIRQL irql;

    KeAcquireSpinLock(&g_State.AskQueueLock, &irql);
    for (PLIST_ENTRY e = g_State.AskQueue.Flink; e != &g_State.AskQueue; e = e->Flink) {
        PASK_QUEUE_NODE n = CONTAINING_RECORD(e, ASK_QUEUE_NODE, ListEntry);
        if (n->Request.RequestId == requestId) {
            RemoveEntryList(&n->ListEntry);
            InitializeListHead(&n->ListEntry);
            removed = TRUE;
            KeReleaseSpinLock(&g_State.AskQueueLock, irql);
            ExFreePool(n);
            return TRUE;
        }
    }
    KeReleaseSpinLock(&g_State.AskQueueLock, irql);

    return removed;
}

NTSTATUS SendAskAndWait(
    _In_ ProtectType type,
    _In_ ActionType action,
    _In_opt_ PCUNICODE_STRING processName,
    _In_opt_ PCUNICODE_STRING processPath,
    _In_opt_ PCUNICODE_STRING resourcePath,
    _In_ INT32 ruleId,
    _In_opt_ PCUNICODE_STRING ruleName,
    _In_ ULONG timeoutSeconds,
    _Out_ Treatment* decision
    )
{
    if (!decision)
        return STATUS_INVALID_PARAMETER;

    *decision = Allow;

    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    NTSTATUS status = STATUS_SUCCESS;

    UINT32 requestId = (UINT32)InterlockedIncrement(&g_State.NextRequestId);

    PPENDING_ASK pending = (PPENDING_ASK)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PENDING_ASK), TAG_POLICY);
    if (!pending) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(pending, sizeof(*pending));
    pending->RequestId = requestId;
    pending->Decision = (UINT32)Ask;
    pending->HasResponse = 0;
    KeInitializeEvent(&pending->ResponseEvent, SynchronizationEvent, FALSE);
    InitializeListHead(&pending->ListEntry);

    ExAcquireFastMutex(&g_State.PendingAskLock);
    InsertTailList(&g_State.PendingAskList, &pending->ListEntry);
    ExReleaseFastMutex(&g_State.PendingAskLock);

    PASK_QUEUE_NODE node = (PASK_QUEUE_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ASK_QUEUE_NODE), TAG_POLICY);
    if (!node) {
        ExAcquireFastMutex(&g_State.PendingAskLock);
        RemoveEntryList(&pending->ListEntry);
        ExReleaseFastMutex(&g_State.PendingAskLock);
        ExFreePool(pending);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(node, sizeof(*node));
    InitializeListHead(&node->ListEntry);

    node->Request.RequestId = requestId;
    node->Request.RuleId = ruleId;
    node->Request.Type = (UINT32)type;
    node->Request.ActionAll = action.all;
    node->Request.TimeoutSeconds = timeoutSeconds;
    CopyUnicodeToBuffer(processName, node->Request.ProcessName, RTL_NUMBER_OF(node->Request.ProcessName));
    CopyUnicodeToBuffer(processPath, node->Request.ProcessPath, RTL_NUMBER_OF(node->Request.ProcessPath));
    CopyUnicodeToBuffer(resourcePath, node->Request.ResourcePath, RTL_NUMBER_OF(node->Request.ResourcePath));
    CopyUnicodeToBuffer(ruleName, node->Request.RuleName, RTL_NUMBER_OF(node->Request.RuleName));

    KIRQL irql;
    KeAcquireSpinLock(&g_State.AskQueueLock, &irql);
    InsertTailList(&g_State.AskQueue, &node->ListEntry);
    KeReleaseSpinLock(&g_State.AskQueueLock, irql);

    KeSetEvent(&g_State.QueueNotEmpty, IO_NO_INCREMENT, FALSE);

    LARGE_INTEGER timeout;
    timeout.QuadPart = -(LONGLONG)timeoutSeconds * 10 * 1000 * 1000;
    
    Log("AskUserForDecision: RequestId=%u waiting...", requestId);
    
    if (g_State.FsRtlCancellableWaitForSingleObject) {
        status = g_State.FsRtlCancellableWaitForSingleObject(&pending->ResponseEvent, &timeout, nullptr);
    }
    else {
        status = KeWaitForSingleObject(&pending->ResponseEvent,
                                        Executive,
                                        KernelMode,
                                        FALSE,
                                        &timeout);
    }
    
    LONG hasResp = InterlockedCompareExchange(&pending->HasResponse, 0, 0);
    Log("AskUserForDecision: RequestId=%u wait returned status=0x%08X, HasResponse=%d, Decision=%u", 
        requestId, status, hasResp, pending->Decision);

    UINT32 finalDecision = (UINT32)Block;
    if (status == STATUS_SUCCESS && hasResp != 0) {
        finalDecision = pending->Decision;
        if (finalDecision == (UINT32)Ask)
            finalDecision = (UINT32)Block;
    }

    (VOID)RemoveAskQueueNodeByRequestId(requestId);

    ExAcquireFastMutex(&g_State.PendingAskLock);
    RemoveEntryList(&pending->ListEntry);
    ExReleaseFastMutex(&g_State.PendingAskLock);
    ExFreePool(pending);

    *decision = (Treatment)finalDecision;

    Log("AskUserForDecision: RequestId=%u finalDecision=%u, returning %s", 
        requestId, finalDecision, 
        (finalDecision == (UINT32)Block) ? "STATUS_IO_TIMEOUT" : "STATUS_SUCCESS");

    if (finalDecision == (UINT32)Block)
        return STATUS_IO_TIMEOUT;

    return STATUS_SUCCESS;
}
