#include "Common.h"
#include "RuleManager.h"
#include "SharedMemory.h"
#include "RegistryCallbacks.h"
#include "ProcessCallbacks.h"
#include "MiniFilterCallbacks.h"

EXTERN_C VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DeviceIoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DefaultDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);

GLOBAL_STATE g_State = { 0 };

static VOID CsqInsertIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp);
static VOID CsqRemoveIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp);
static PIRP CsqPeekNextIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp, _In_opt_ PVOID PeekContext);
static VOID CsqAcquireLock(_In_ PIO_CSQ Csq, _Out_ PKIRQL Irql);
static VOID CsqReleaseLock(_In_ PIO_CSQ Csq, _In_ KIRQL Irql);
static VOID CsqCompleteCanceledIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp);
static VOID AskWorkerThreadStart(_In_ PVOID StartContext);
static BOOLEAN TryDeliverOneAskToWaitingIrp();
static VOID ResolveOptionalRoutines();

PCSQ_IRP_CONTEXT GetIrpCsqContext(_In_ PIRP Irp)
{
    return (PCSQ_IRP_CONTEXT)Irp->Tail.Overlay.DriverContext[0];
}

VOID SetIrpCsqContext(_In_ PIRP Irp, _In_opt_ PCSQ_IRP_CONTEXT Ctx)
{
    Irp->Tail.Overlay.DriverContext[0] = Ctx;
}


EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driver, UNICODE_STRING path)
{
    UNREFERENCED_PARAMETER(path);

    NTSTATUS status = STATUS_SUCCESS;

    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\1zGuard");

    BOOLEAN deviceCreated = FALSE;
    BOOLEAN symbolicLinkCreated = FALSE;
    BOOLEAN workerThreadCreated = FALSE;
    BOOLEAN workerThreadReferenced = FALSE;
    BOOLEAN sharedMemoryInitialized = FALSE;
    BOOLEAN registryCallbackInitialized = FALSE;
    BOOLEAN processCallbackInitialized = FALSE;
    BOOLEAN miniFilterInitialized = FALSE;

    driver->DriverUnload = DriverUnload;

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        driver->MajorFunction[i] = DefaultDispatch;
    }

    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlHandler;

    g_State.pRuleManager = (RuleManager*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(RuleManager),
        'RMge'
    );

    if (!g_State.pRuleManager)
    {
        Log("Alloc RuleManager mem failed");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_State.pRuleManager, sizeof(RuleManager));

    status = g_State.pRuleManager->Initialize();

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = IoCreateDevice(
        driver,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_State.pDeviceObject
    );
    if (!NT_SUCCESS(status)) {
        Log("Failed to create device: 0x%08X", status);
        goto Exit;
    }
    deviceCreated = TRUE;

    g_State.SymbolicLinkName = RTL_CONSTANT_STRING(L"\\??\\1zGuard");

    status = IoCreateSymbolicLink(&g_State.SymbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        Log("Failed to create symbolic link: 0x%08X", status);
        goto Exit;
    }
    symbolicLinkCreated = TRUE;

    InitializeListHead(&g_State.PendingList);
    KeInitializeSpinLock(&g_State.QueueLock);
    IoCsqInitialize(&g_State.CsqQueue,
                    CsqInsertIrp,
                    CsqRemoveIrp,
                    CsqPeekNextIrp,
                    CsqAcquireLock,
                    CsqReleaseLock,
                    CsqCompleteCanceledIrp);

    InitializeListHead(&g_State.AskQueue);
    KeInitializeSpinLock(&g_State.AskQueueLock);
    InitializeListHead(&g_State.PendingAskList);
    ExInitializeFastMutex(&g_State.PendingAskLock);

    KeInitializeSpinLock(&g_State.ClientPathLock);
    RtlZeroMemory(g_State.ClientProcessPath, sizeof(g_State.ClientProcessPath));

    KeInitializeSpinLock(&g_State.MainProcessIdLock);
    g_State.MainProcessId = nullptr;

    g_State.WorkerThreadHandle = nullptr;
    g_State.WorkerThread = nullptr;
    KeInitializeEvent(&g_State.WorkerShutdown, NotificationEvent, FALSE);
    KeInitializeEvent(&g_State.QueueNotEmpty, NotificationEvent, FALSE);

    ResolveOptionalRoutines();

    status = PsCreateSystemThread(
        &g_State.WorkerThreadHandle,
        THREAD_ALL_ACCESS,
        nullptr,
        nullptr,
        nullptr,
        AskWorkerThreadStart,
        nullptr);
    if (!NT_SUCCESS(status)) {
        Log("PsCreateSystemThread failed: 0x%08X", status);
        goto Exit;
    }
    workerThreadCreated = TRUE;

    status = ObReferenceObjectByHandle(
        g_State.WorkerThreadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&g_State.WorkerThread,
        nullptr);
    if (!NT_SUCCESS(status)) {
        Log("ObReferenceObjectByHandle(WorkerThread) failed: 0x%08X", status);
        goto Exit;
    }
    workerThreadReferenced = TRUE;

    status = InitializeSharedMemory(driver);
    if (!NT_SUCCESS(status)) {
        Log("InitializeSharedMemory failed: 0x%08X", status);
        goto Exit;
    }
    sharedMemoryInitialized = TRUE;

    status = InitializeRegistryCallback(driver);
    if (!NT_SUCCESS(status)) {
        Log("InitializeRegistryCallback failed: 0x%08X", status);
        goto Exit;
    }
    registryCallbackInitialized = TRUE;

    status = InitializeProcessCallback(driver);
    if (!NT_SUCCESS(status)) {
        Log("InitializeProcessCallback failed: 0x%08X", status);
        goto Exit;
    }
    processCallbackInitialized = TRUE;

    status = InitializeMiniFilter(driver);
    if (!NT_SUCCESS(status)) {
        Log("InitializeMiniFilter failed: 0x%08X", status);
        goto Exit;
    }
    miniFilterInitialized = TRUE;

    InterlockedExchange(&g_State.ProtectionEnabled, 0);

    Log("=== Driver Loaded Successfully ===");

    return STATUS_SUCCESS;

Exit:
    if (miniFilterInitialized) {
        UninitializeMiniFilter();
        miniFilterInitialized = FALSE;
    }
    if (processCallbackInitialized) {
        UninitializeProcessCallback();
        processCallbackInitialized = FALSE;
    }
    if (registryCallbackInitialized) {
        UninitializeRegistryCallback();
        registryCallbackInitialized = FALSE;
    }
    if (sharedMemoryInitialized) {
        UninitializeSharedMemory();
        sharedMemoryInitialized = FALSE;
    }

    if (workerThreadCreated) {
        KeSetEvent(&g_State.WorkerShutdown, IO_NO_INCREMENT, FALSE);
        KeSetEvent(&g_State.QueueNotEmpty, IO_NO_INCREMENT, FALSE);
    }

    if (workerThreadReferenced && g_State.WorkerThread) {
        KeWaitForSingleObject(g_State.WorkerThread, Executive, KernelMode, FALSE, nullptr);
        ObDereferenceObject(g_State.WorkerThread);
        g_State.WorkerThread = nullptr;
        workerThreadReferenced = FALSE;
    }

    if (workerThreadCreated && g_State.WorkerThreadHandle) {
        ZwWaitForSingleObject(g_State.WorkerThreadHandle, FALSE, nullptr);
        ZwClose(g_State.WorkerThreadHandle);
        g_State.WorkerThreadHandle = nullptr;
        workerThreadCreated = FALSE;
    }

    if (symbolicLinkCreated) {
        IoDeleteSymbolicLink(&g_State.SymbolicLinkName);
        symbolicLinkCreated = FALSE;
    }

    if (deviceCreated && g_State.pDeviceObject) {
        IoDeleteDevice(g_State.pDeviceObject);
        g_State.pDeviceObject = nullptr;
        deviceCreated = FALSE;
    }

    if (g_State.pRuleManager) {
        g_State.pRuleManager->Uninitialize();
        ExFreePool(g_State.pRuleManager);
        g_State.pRuleManager = nullptr;
    }

    return status;
}

static VOID ResolveOptionalRoutines()
{
    g_State.FsRtlCancellableWaitForSingleObject = nullptr;

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"FsRtlCancellableWaitForSingleObject");
    g_State.FsRtlCancellableWaitForSingleObject =
        (PFN_FsRtlCancellableWaitForSingleObject)MmGetSystemRoutineAddress(&name);
}

static VOID CsqInsertIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    InsertTailList(&g_State.PendingList, &Irp->Tail.Overlay.ListEntry);
}

static VOID CsqRemoveIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

static PIRP CsqPeekNextIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp, _In_opt_ PVOID PeekContext)
{
    UNREFERENCED_PARAMETER(Csq);
    UNREFERENCED_PARAMETER(PeekContext);

    PLIST_ENTRY entry;
    if (Irp == nullptr) {
        entry = g_State.PendingList.Flink;
    }
    else {
        entry = Irp->Tail.Overlay.ListEntry.Flink;
    }

    if (entry == &g_State.PendingList)
        return nullptr;

    return CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
}

static VOID CsqAcquireLock(_In_ PIO_CSQ Csq, _Out_ PKIRQL Irql)
{
    UNREFERENCED_PARAMETER(Csq);
    KeAcquireSpinLock(&g_State.QueueLock, Irql);
}

static VOID CsqReleaseLock(_In_ PIO_CSQ Csq, _In_ KIRQL Irql)
{
    UNREFERENCED_PARAMETER(Csq);
    KeReleaseSpinLock(&g_State.QueueLock, Irql);
}

static VOID CsqCompleteCanceledIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);

    PCSQ_IRP_CONTEXT ctx = GetIrpCsqContext(Irp);
    if (ctx) {
        SetIrpCsqContext(Irp, nullptr);
        ExFreePool(ctx);
    }

    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

static BOOLEAN TryDeliverOneAskToWaitingIrp()
{
    PASK_QUEUE_NODE node = nullptr;
    KIRQL askIrql;

    KeAcquireSpinLock(&g_State.AskQueueLock, &askIrql);
    if (!IsListEmpty(&g_State.AskQueue)) {
        PLIST_ENTRY e = RemoveHeadList(&g_State.AskQueue);
        node = CONTAINING_RECORD(e, ASK_QUEUE_NODE, ListEntry);
    }
    KeReleaseSpinLock(&g_State.AskQueueLock, askIrql);

    if (!node)
        return FALSE;

    PIRP irp = IoCsqRemoveNextIrp(&g_State.CsqQueue, nullptr);
    if (!irp) {
        KIRQL irql;
        KeAcquireSpinLock(&g_State.AskQueueLock, &irql);
        InsertHeadList(&g_State.AskQueue, &node->ListEntry);
        KeReleaseSpinLock(&g_State.AskQueueLock, irql);
        return FALSE;
    }

    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;

    if (outLen >= sizeof(USER_ASK_REQUEST)) {
        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &node->Request, sizeof(USER_ASK_REQUEST));
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = sizeof(USER_ASK_REQUEST);
    }
    else {
        irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        irp->IoStatus.Information = 0;
    }

    PCSQ_IRP_CONTEXT ctx = GetIrpCsqContext(irp);
    if (ctx) {
        SetIrpCsqContext(irp, nullptr);
        ExFreePool(ctx);
    }

    ExFreePool(node);
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return TRUE;
}

static VOID AskWorkerThreadStart(_In_ PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    PVOID waitObjects[2];
    waitObjects[0] = &g_State.WorkerShutdown;
    waitObjects[1] = &g_State.QueueNotEmpty;

    for (;;) {
        NTSTATUS waitStatus = KeWaitForMultipleObjects(
            2,
            waitObjects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            nullptr,
            nullptr);

        if (waitStatus == STATUS_WAIT_0) {
            break;
        }

        KeClearEvent(&g_State.QueueNotEmpty);
        while (TryDeliverOneAskToWaitingIrp()) {
            // 添加 0.8 秒延时，避免弹窗过于频繁
            LARGE_INTEGER delayInterval;
            delayInterval.QuadPart = -8000000LL;
            KeDelayExecutionThread(KernelMode, FALSE, &delayInterval);
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

EXTERN_C VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    InterlockedExchange(&g_State.MiniFilterShutdown, 1);
    InterlockedExchange(&g_State.ProtectionEnabled, 0);

    KeSetEvent(&g_State.WorkerShutdown, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&g_State.QueueNotEmpty, IO_NO_INCREMENT, FALSE);

    if (g_State.WorkerThread) {
        KeWaitForSingleObject(g_State.WorkerThread, Executive, KernelMode, FALSE, nullptr);
        ObDereferenceObject(g_State.WorkerThread);
        g_State.WorkerThread = nullptr;
    }

    if (g_State.WorkerThreadHandle) {
        ZwClose(g_State.WorkerThreadHandle);
        g_State.WorkerThreadHandle = nullptr;
    }

    for (;;) {
        PIRP irp = IoCsqRemoveNextIrp(&g_State.CsqQueue, nullptr);
        if (!irp)
            break;

        PCSQ_IRP_CONTEXT ctx = GetIrpCsqContext(irp);
        if (ctx) {
            SetIrpCsqContext(irp, nullptr);
            ExFreePool(ctx);
        }

        irp->IoStatus.Status = STATUS_CANCELLED;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }

    for (;;) {
        PASK_QUEUE_NODE node = nullptr;
        KIRQL irql;
        KeAcquireSpinLock(&g_State.AskQueueLock, &irql);
        if (!IsListEmpty(&g_State.AskQueue)) {
            PLIST_ENTRY e = RemoveHeadList(&g_State.AskQueue);
            node = CONTAINING_RECORD(e, ASK_QUEUE_NODE, ListEntry);
        }
        KeReleaseSpinLock(&g_State.AskQueueLock, irql);

        if (!node)
            break;
        ExFreePool(node);
    }

    ExAcquireFastMutex(&g_State.PendingAskLock);
    for (PLIST_ENTRY e = g_State.PendingAskList.Flink; e != &g_State.PendingAskList; e = e->Flink) {
        PPENDING_ASK pending = CONTAINING_RECORD(e, PENDING_ASK, ListEntry);
        pending->Decision = (UINT32)Block;
        InterlockedExchange(&pending->HasResponse, 1);
        KeSetEvent(&pending->ResponseEvent, IO_NO_INCREMENT, FALSE);
    }
    ExReleaseFastMutex(&g_State.PendingAskLock);

    UninitializeMiniFilter();
    UninitializeProcessCallback();
    UninitializeRegistryCallback();
    UninitializeSharedMemory();

    if (g_State.pRuleManager) {
        g_State.pRuleManager->Uninitialize();
        ExFreePool(g_State.pRuleManager);
    }

    if (g_State.SymbolicLinkName.Buffer) {
        IoDeleteSymbolicLink(&g_State.SymbolicLinkName);
    }

    if (g_State.pDeviceObject) {
        IoDeleteDevice(g_State.pDeviceObject);
    }

    Log("=== Driver Unloaded ===");
}

NTSTATUS DeviceIoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;

    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (ioctl) {
    case IOCTL_TOGGLE_PROTECTION: {
        if (inputLength >= sizeof(BOOLEAN)) {
            BOOLEAN enable = *(BOOLEAN*)buffer;
            InterlockedExchange(&g_State.ProtectionEnabled, enable ? 1 : 0);
            Log("IOCTL_TOGGLE_PROTECTION: %s", enable ? "Enabled" : "Disabled");
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    }
    case IOCTL_BATCH_ADD_RULES: {
        if (inputLength < sizeof(USER_BATCH_RULE_REQUEST)) {
            status = STATUS_INVALID_PARAMETER;
            Log("IOCTL_BATCH_ADD_RULES: Buffer too small");
            break;
        }

        USER_BATCH_RULE_REQUEST* req = (USER_BATCH_RULE_REQUEST*)buffer;
        UCHAR* cursor = req->Data;
        SIZE_T remaining = inputLength - FIELD_OFFSET(USER_BATCH_RULE_REQUEST, Data);

        if (req->RuleCount == 0) {
            status = STATUS_INVALID_PARAMETER;
            Log("IOCTL_BATCH_ADD_RULES: RuleCount == 0");
            break;
        }

        Log("IOCTL_BATCH_ADD_RULES: Batch loading %u rules", req->RuleCount);

        for (UINT32 i = 0; i < req->RuleCount; i++) {
            if (remaining < sizeof(USER_RULE)) {
                status = STATUS_INVALID_PARAMETER;
                Log("IOCTL_BATCH_ADD_RULES: Remaining too small for USER_RULE");
                break;
            }

            USER_RULE* userRule = (USER_RULE*)cursor;

            UINT32 totalPolicies =
                userRule->ProcessCount +
                userRule->FileCount +
                userRule->RegistryCount;

            SIZE_T ruleSize =
                FIELD_OFFSET(USER_RULE, Policies) +
                ((SIZE_T)totalPolicies) * sizeof(USER_POLICY);

            if (remaining < ruleSize) {
                status = STATUS_INVALID_PARAMETER;
                Log("IOCTL_BATCH_ADD_RULES: Rule %u size mismatch", i);
                break;
            }

            RuleItem* tmp = g_State.pRuleManager->AllocateRuleItem();
            if (!tmp) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                Log("IOCTL_BATCH_ADD_RULES: AllocateRuleItem failed on rule %u", i);
                break;
            }

            RtlZeroMemory(tmp, sizeof(RuleItem));
            InitializeListHead(&tmp->ListEntry);

            NTSTATUS s = g_State.pRuleManager->BuildRuleItemFromUserRule(userRule, tmp);
            if (NT_SUCCESS(s)) {
                s = g_State.pRuleManager->UpdateRule(userRule->Id, tmp);
                if (!NT_SUCCESS(s)) {
                    Log("IOCTL_BATCH_ADD_RULES: UpdateRule failed for id=%d, status=0x%08X",
                        userRule->Id, s);
                }
            }
            else {
                Log("IOCTL_BATCH_ADD_RULES: BuildRuleItemFromUserRule failed: 0x%08X", s);
            }

            g_State.pRuleManager->FreeRuleItem(tmp);

            cursor += ruleSize;
            remaining -= ruleSize;
        }

        break;
    }

    case IOCTL_ADD_RULE: {
        if (inputLength < sizeof(USER_RULE)) {
            status = STATUS_INVALID_PARAMETER;
            Log("IOCTL_ADD_RULE: Buffer too small for USER_RULE");
            break;
        }

        USER_RULE* userRule = (USER_RULE*)buffer;

        UINT32 totalPolicies =
            userRule->ProcessCount +
            userRule->FileCount +
            userRule->RegistryCount;

        SIZE_T expectedSize =
            FIELD_OFFSET(USER_RULE, Policies) +
            ((SIZE_T)totalPolicies) * sizeof(USER_POLICY);

        if (inputLength < expectedSize) {
            status = STATUS_INVALID_PARAMETER;
            Log("IOCTL_ADD_RULE: Buffer size mismatch, expected %Iu, got %lu",
                expectedSize, inputLength);
            break;
        }

        RuleItem* tmp = g_State.pRuleManager->AllocateRuleItem();
        if (!tmp) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            Log("IOCTL_ADD_RULE: AllocateRuleItem failed");
            break;
        }

        RtlZeroMemory(tmp, sizeof(RuleItem));
        InitializeListHead(&tmp->ListEntry);

        status = g_State.pRuleManager->BuildRuleItemFromUserRule(userRule, tmp);
        if (NT_SUCCESS(status)) {
            Log("IOCTL_ADD_RULE: ID=%d", userRule->Id);
            status = g_State.pRuleManager->UpdateRule(userRule->Id, tmp);
            Log("IOCTL_ADD_RULE: Status = 0x%08X", status);
        }
        else {
            Log("IOCTL_ADD_RULE: BuildRuleItemFromUserRule failed: 0x%08X", status);
        }

        g_State.pRuleManager->FreeRuleItem(tmp);
        break;
    }

    case IOCTL_DELETE_RULE: {
        if (inputLength < sizeof(INT32))
        {
            status = STATUS_INVALID_PARAMETER;
            Log("IOCTL_DELETE_RULE: Invalid parameter size");
            break;
        }

        INT32* data = (INT32*)buffer;
        UINT32 count = (UINT32)data[0];

        if (count == 0 || inputLength < (static_cast<UINT64>(count) + 1) * sizeof(INT32)) {
            status = STATUS_INVALID_PARAMETER;
            Log("IOCTL_DELETE_RULE: Invalid parameter size");
            break;
        }

        for (UINT32 i = 1; i <= count; i++) {
            INT32 id = data[i];
            g_State.pRuleManager->DeleteRule(id);
            Log("IOCTL_DELETE_RULE: Deleting ID=%d", id);
        }
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_CLEAR_RULES: {
        Log("IOCTL_CLEAR_RULES: Clearing all rules");
        g_State.pRuleManager->ClearAll();
        Log("IOCTL_CLEAR_RULES: Completed");
        break;
    }

    case IOCTL_GET_NEXT_ASK: {
        if (outputLength < sizeof(USER_ASK_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
             Log("IOCTL_GET_NEXT_ASK: STATUS_BUFFER_TOO_SMALL");
            break;
        }

        PCSQ_IRP_CONTEXT ctx = (PCSQ_IRP_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CSQ_IRP_CONTEXT), TAG_POLICY);
        if (!ctx) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            Log("IOCTL_GET_NEXT_ASK: STATUS_INSUFFICIENT_RESOURCES");
            break;
        }
        RtlZeroMemory(ctx, sizeof(*ctx));
        SetIrpCsqContext(Irp, ctx);

        IoMarkIrpPending(Irp);
        IoCsqInsertIrp(&g_State.CsqQueue, Irp, &ctx->CsqContext);
        KeSetEvent(&g_State.QueueNotEmpty, IO_NO_INCREMENT, FALSE);
        Log("IOCTL_GET_NEXT_ASK: Completed");
        return STATUS_PENDING;
    }

    case IOCTL_RESPOND_ASK: {
        if (inputLength < sizeof(USER_ASK_RESPONSE)) {
            status = STATUS_INVALID_PARAMETER;
            Log("IOCTL_RESPOND_ASK: Invalid parameter size");
            break;
        }

        USER_ASK_RESPONSE* resp = (USER_ASK_RESPONSE*)buffer;
        Log("IOCTL_RESPOND_ASK: Received RequestId=%u, Decision=%u", resp->RequestId, resp->Decision);

        PPENDING_ASK target = nullptr;

        Log("IOCTL_RESPOND_ASK: Acquiring PendingAskLock...");
        ExAcquireFastMutex(&g_State.PendingAskLock);
        Log("IOCTL_RESPOND_ASK: Lock acquired, searching list...");
        int count = 0;
        for (PLIST_ENTRY e = g_State.PendingAskList.Flink; e != &g_State.PendingAskList; e = e->Flink) {
            PPENDING_ASK pa = CONTAINING_RECORD(e, PENDING_ASK, ListEntry);
            Log("IOCTL_RESPOND_ASK: PendingList[%d] RequestId=%u", count++, pa->RequestId);
            if (pa->RequestId == resp->RequestId) {
                target = pa;
                break;
            }
        }

        if (target) {
            target->Decision = resp->Decision;
            InterlockedExchange(&target->HasResponse, 1);
            ExReleaseFastMutex(&g_State.PendingAskLock);
            KeSetEvent(&target->ResponseEvent, IO_NO_INCREMENT, FALSE);
            status = STATUS_SUCCESS;
            Log("IOCTL_RESPOND_ASK: SUCCESS - signaled event for RequestId=%u", resp->RequestId);
        } else {
            ExReleaseFastMutex(&g_State.PendingAskLock);
            status = STATUS_NOT_FOUND;
            Log("IOCTL_RESPOND_ASK: NOT_FOUND - RequestId=%u not in list (list has %d items)", resp->RequestId, count);
        }
        break;
    }

    case IOCTL_REGISTER_CLIENT: {
        // 客户端注册自己的进程路径，驱动会将其加入白名单
        if (inputLength < sizeof(WCHAR) * 2) {
            status = STATUS_INVALID_PARAMETER;
            Log("IOCTL_REGISTER_CLIENT: Buffer too small");
            break;
        }

        PCWCHAR clientPath = (PCWCHAR)buffer;
        SIZE_T maxChars = inputLength / sizeof(WCHAR);
        if (maxChars > RTL_NUMBER_OF(g_State.ClientProcessPath) - 1) {
            maxChars = RTL_NUMBER_OF(g_State.ClientProcessPath) - 1;
        }

        SIZE_T pathLen = 0;
        for (SIZE_T i = 0; i < maxChars; i++) {
            if (clientPath[i] == L'\0') {
                pathLen = i;
                break;
            }
            pathLen = i + 1;
        }

        KIRQL irql;
        KeAcquireSpinLock(&g_State.ClientPathLock, &irql);
        RtlZeroMemory(g_State.ClientProcessPath, sizeof(g_State.ClientProcessPath));
        RtlCopyMemory(g_State.ClientProcessPath, clientPath, pathLen * sizeof(WCHAR));
        g_State.ClientProcessPath[pathLen] = L'\0';
        KeReleaseSpinLock(&g_State.ClientPathLock, irql);

        // 保存当前进程ID作为主客户端进程
        HANDLE currentPid = PsGetCurrentProcessId();
        KeAcquireSpinLock(&g_State.MainProcessIdLock, &irql);
        g_State.MainProcessId = currentPid;
        KeReleaseSpinLock(&g_State.MainProcessIdLock, irql);

        Log("IOCTL_REGISTER_CLIENT: Registered client path: %ws, PID: %p", g_State.ClientProcessPath, currentPid);
        status = STATUS_SUCCESS;
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        Log("Unknown IOCTL: 0x%08X", ioctl);
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS DefaultDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}