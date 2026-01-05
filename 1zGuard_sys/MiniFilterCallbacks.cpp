#include "MiniFilterCallbacks.h"
#include <ntifs.h>
#include <ntstrsafe.h>

extern "C" GLOBAL_STATE g_State;

static NTSTATUS GetProcessNameByPid(_In_ HANDLE pid, _Out_ PUNICODE_STRING ProcessName)
{
    if (!ProcessName)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(ProcessName, sizeof(*ProcessName));

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status) || !process)
        return status;

    PUNICODE_STRING imagePath = nullptr;
    status = SeLocateProcessImageName(process, &imagePath);
    if (NT_SUCCESS(status) && imagePath && imagePath->Buffer && imagePath->Length) {
        status = RtlDuplicateUnicodeString(
            RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
            imagePath,
            ProcessName);
    }
    else {
        status = STATUS_UNSUCCESSFUL;
    }

    if (imagePath)
        ExFreePool(imagePath);

    ObfDereferenceObject(process);
    return status;
}

static BOOLEAN DuplicateUnicodeStringSafe(_In_ PCUNICODE_STRING src, _Out_ PUNICODE_STRING dst)
{
    RtlZeroMemory(dst, sizeof(*dst));
    if (!src || !src->Buffer || src->Length == 0)
        return FALSE;

    NTSTATUS status = RtlDuplicateUnicodeString(
        RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
        src,
        dst);

    return NT_SUCCESS(status) && dst->Buffer;
}

static BOOLEAN TryConvertNtDevicePathToDosPath(
    _In_ PFLT_VOLUME Volume,
    _In_ PCUNICODE_STRING NtPath,
    _Out_ PUNICODE_STRING DosPath)
{
    RtlZeroMemory(DosPath, sizeof(*DosPath));
    if (!Volume || !NtPath || !NtPath->Buffer || NtPath->Length < sizeof(WCHAR))
        return FALSE;

    static const WCHAR kDevicePrefix[] = L"\\Device\\";
    UNICODE_STRING devicePrefix;
    RtlInitUnicodeString(&devicePrefix, kDevicePrefix);
    if (!RtlPrefixUnicodeString(&devicePrefix, NtPath, TRUE))
        return FALSE;

    ULONG lenChars = NtPath->Length / sizeof(WCHAR);
    ULONG slashCount = 0;
    ULONG remainderIndex = 0;
    for (ULONG i = 0; i < lenChars; i++) {
        if (NtPath->Buffer[i] == L'\\') {
            slashCount++;
            if (slashCount == 3) {
                remainderIndex = i;
                break;
            }
        }
    }
    if (slashCount < 3)
        return FALSE;

    USHORT remainderOffsetBytes = (USHORT)(remainderIndex * sizeof(WCHAR));
    if (remainderOffsetBytes >= NtPath->Length)
        return FALSE;

    UNICODE_STRING dosName = { 0 };
    PDEVICE_OBJECT diskDeviceObject = nullptr;
    NTSTATUS status = FltGetDiskDeviceObject(Volume, &diskDeviceObject);
    if (!NT_SUCCESS(status) || !diskDeviceObject)
        return FALSE;

    status = IoVolumeDeviceToDosName(diskDeviceObject, &dosName);
    ObDereferenceObject(diskDeviceObject);
    if (!NT_SUCCESS(status) || !dosName.Buffer || dosName.Length == 0)
        return FALSE;

    USHORT remainderLenBytes = (USHORT)(NtPath->Length - remainderOffsetBytes);
    USHORT outLenBytes = (USHORT)(dosName.Length + remainderLenBytes);
    PWCHAR outBuf = (PWCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        (SIZE_T)outLenBytes + sizeof(WCHAR),
        TAG_STRING);

    if (!outBuf) {
        ExFreePool(dosName.Buffer);
        return FALSE;
    }

    RtlCopyMemory(outBuf, dosName.Buffer, dosName.Length);
    RtlCopyMemory((PUCHAR)outBuf + dosName.Length, (PUCHAR)NtPath->Buffer + remainderOffsetBytes, remainderLenBytes);
    outBuf[outLenBytes / sizeof(WCHAR)] = L'\0';

    DosPath->Buffer = outBuf;
    DosPath->Length = outLenBytes;
    DosPath->MaximumLength = (USHORT)(outLenBytes + sizeof(WCHAR));

    ExFreePool(dosName.Buffer);
    return TRUE;
}

static ActionType BuildActionFromMajorAndData(_In_ UCHAR major, _In_ PFLT_CALLBACK_DATA Data)
{
    ActionType action = { 0 };

    switch (major) {
    case IRP_MJ_CREATE: {
        ULONG options = Data->Iopb->Parameters.Create.Options;

        BOOLEAN deleteOnClose = FlagOn(options, FILE_DELETE_ON_CLOSE) ? TRUE : FALSE;

        if (deleteOnClose) {
            action.fields.Delete = 1;
            break;
        }

        ULONG disposition = (options >> 24) & 0xFF;
        if (disposition == FILE_CREATE || disposition == FILE_SUPERSEDE) {
            action.fields.Create = 1;
        }
        break;
    }
    case IRP_MJ_READ:
        action.fields.Read = 1;
        break;
    case IRP_MJ_WRITE:
    case IRP_MJ_SET_EA:
    case IRP_MJ_SET_SECURITY:
        action.fields.Modify = 1;
        break;
    case IRP_MJ_SET_INFORMATION: {
        FILE_INFORMATION_CLASS fic = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        if (fic == FileDispositionInformation || fic == FileDispositionInformationEx) {
            action.fields.Delete = 1;
        }
        else if (fic == FileRenameInformation || fic == FileRenameInformationEx) {
            action.fields.Modify = 1;
        }
        else if (fic == FileBasicInformation || fic == FileEndOfFileInformation || fic == FileAllocationInformation) {
            action.fields.Modify = 1;
        }
        break;
    }
    case IRP_MJ_CLEANUP:
    //case IRP_MJ_CLOSE:
        if (Data->Iopb && Data->Iopb->TargetFileObject && Data->Iopb->TargetFileObject->DeletePending) {
            action.fields.Delete = 1;
        }
        break;
    default:
        break;
    }

    return action;
}

static FLT_PREOP_CALLBACK_STATUS CommonPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    InterlockedIncrement(&g_State.MiniFilterPendingOps);
    KeClearEvent(&g_State.MiniFilterNoPendingOps);

    // 如果正在卸载，直接放行
    if (InterlockedCompareExchange(&g_State.MiniFilterShutdown, 0, 0) != 0) {
        if (InterlockedDecrement(&g_State.MiniFilterPendingOps) == 0)
            KeSetEvent(&g_State.MiniFilterNoPendingOps, IO_NO_INCREMENT, FALSE);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!g_State.pRuleManager) {
        if (InterlockedDecrement(&g_State.MiniFilterPendingOps) == 0)
            KeSetEvent(&g_State.MiniFilterNoPendingOps, IO_NO_INCREMENT, FALSE);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (InterlockedCompareExchange(&g_State.ProtectionEnabled, 0, 0) == 0) {
        if (InterlockedDecrement(&g_State.MiniFilterPendingOps) == 0)
            KeSetEvent(&g_State.MiniFilterNoPendingOps, IO_NO_INCREMENT, FALSE);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 客户端进程白名单：跳过客户端自己的操作
    if (IsCurrentProcessClient()) {
        if (InterlockedDecrement(&g_State.MiniFilterPendingOps) == 0)
            KeSetEvent(&g_State.MiniFilterNoPendingOps, IO_NO_INCREMENT, FALSE);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        if (InterlockedDecrement(&g_State.MiniFilterPendingOps) == 0)
            KeSetEvent(&g_State.MiniFilterNoPendingOps, IO_NO_INCREMENT, FALSE);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!Data || !Data->Iopb) {
        if (InterlockedDecrement(&g_State.MiniFilterPendingOps) == 0)
            KeSetEvent(&g_State.MiniFilterNoPendingOps, IO_NO_INCREMENT, FALSE);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ActionType action = BuildActionFromMajorAndData(Data->Iopb->MajorFunction, Data);
    if (action.all == 0) {
        if (InterlockedDecrement(&g_State.MiniFilterPendingOps) == 0)
            KeSetEvent(&g_State.MiniFilterNoPendingOps, IO_NO_INCREMENT, FALSE);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    HANDLE pid = (HANDLE)(ULONG_PTR)FltGetRequestorProcessId(Data);
    UNICODE_STRING processName = { 0 };
    BOOLEAN hasProc = NT_SUCCESS(GetProcessNameByPid(pid, &processName)) && processName.Buffer;

    PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;
    NTSTATUS nameStatus = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);

    if (!NT_SUCCESS(nameStatus) || !nameInfo) {
        if (hasProc) RtlFreeUnicodeString(&processName);
        if (InterlockedDecrement(&g_State.MiniFilterPendingOps) == 0)
            KeSetEvent(&g_State.MiniFilterNoPendingOps, IO_NO_INCREMENT, FALSE);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    (VOID)FltParseFileNameInformation(nameInfo);

    UNICODE_STRING filePathDup = { 0 };
    BOOLEAN hasPath = DuplicateUnicodeStringSafe(&nameInfo->Name, &filePathDup);
    FltReleaseFileNameInformation(nameInfo);

    if (!hasPath) {
        if (hasProc) RtlFreeUnicodeString(&processName);
        if (InterlockedDecrement(&g_State.MiniFilterPendingOps) == 0)
            KeSetEvent(&g_State.MiniFilterNoPendingOps, IO_NO_INCREMENT, FALSE);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    UNICODE_STRING dosPath = { 0 };
    BOOLEAN filePathFromPool = FALSE;
    if (TryConvertNtDevicePathToDosPath(FltObjects->Volume, &filePathDup, &dosPath)) {
        RtlFreeUnicodeString(&filePathDup);
        filePathDup = dosPath;
        filePathFromPool = TRUE;
    }

    INT32 ruleId = -1;
    WCHAR ruleNameBuf[64] = { 0 };
    UINT8 treatmentByte = g_State.pRuleManager->MatchFileEx(
        hasProc ? &processName : nullptr,
        action,
        &filePathDup,
        &ruleId,
        ruleNameBuf,
        RTL_NUMBER_OF(ruleNameBuf));

    Treatment treatment = (Treatment)treatmentByte;

    if (treatment == Allow) {
        goto CleanupAndSuccess;
    }

    if (treatment == Block) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        FltSetCallbackDataDirty(Data);
        goto CleanupAndComplete;
    }

    if (treatment == Ask) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            FltSetCallbackDataDirty(Data);
            goto CleanupAndComplete;
        }

        // 检查是否正在关闭，如果是则直接拒绝
        if (InterlockedCompareExchange(&g_State.MiniFilterShutdown, 0, 0) != 0) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            FltSetCallbackDataDirty(Data);
            goto CleanupAndComplete;
        }

        // 直接在当前线程同步处理 Ask
        UNICODE_STRING ruleName;
        RtlInitUnicodeString(&ruleName, ruleNameBuf);

        Treatment decision = Allow;
        NTSTATUS askStatus = SendAskAndWait(
            File,
            action,
            hasProc ? &processName : nullptr,
            nullptr,
            &filePathDup,
            ruleId,
            (ruleName.Buffer ? &ruleName : nullptr),
            30,
            &decision);

        // 再次检查是否正在关闭，如果是则拒绝请求
        if (InterlockedCompareExchange(&g_State.MiniFilterShutdown, 0, 0) != 0) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            FltSetCallbackDataDirty(Data);
            goto CleanupAndComplete;
        }

        if (!NT_SUCCESS(askStatus) || decision == Block) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            FltSetCallbackDataDirty(Data);
            goto CleanupAndComplete;
        }

        goto CleanupAndSuccess;
    }

CleanupAndSuccess:
    if (filePathFromPool) {
        if (filePathDup.Buffer) ExFreePoolWithTag(filePathDup.Buffer, TAG_STRING);
    } else {
        RtlFreeUnicodeString(&filePathDup);
    }
    if (hasProc) RtlFreeUnicodeString(&processName);
    if (InterlockedDecrement(&g_State.MiniFilterPendingOps) == 0)
        KeSetEvent(&g_State.MiniFilterNoPendingOps, IO_NO_INCREMENT, FALSE);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;

CleanupAndComplete:
    if (filePathFromPool) {
        if (filePathDup.Buffer) ExFreePoolWithTag(filePathDup.Buffer, TAG_STRING);
    } else {
        RtlFreeUnicodeString(&filePathDup);
    }
    if (hasProc) RtlFreeUnicodeString(&processName);
    if (InterlockedDecrement(&g_State.MiniFilterPendingOps) == 0)
        KeSetEvent(&g_State.MiniFilterNoPendingOps, IO_NO_INCREMENT, FALSE);
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    return CommonPreOperation(Data, FltObjects, CompletionContext);
}

static FLT_PREOP_CALLBACK_STATUS PreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    return CommonPreOperation(Data, FltObjects, CompletionContext);
}

static FLT_PREOP_CALLBACK_STATUS PreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    return CommonPreOperation(Data, FltObjects, CompletionContext);
}

static FLT_PREOP_CALLBACK_STATUS PreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    return CommonPreOperation(Data, FltObjects, CompletionContext);
}

static FLT_PREOP_CALLBACK_STATUS PreSetEa(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    return CommonPreOperation(Data, FltObjects, CompletionContext);
}

static FLT_PREOP_CALLBACK_STATUS PreSetSecurity(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    return CommonPreOperation(Data, FltObjects, CompletionContext);
}

static FLT_PREOP_CALLBACK_STATUS PreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    return CommonPreOperation(Data, FltObjects, CompletionContext);
}

static NTSTATUS MiniFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    InterlockedExchange(&g_State.MiniFilterShutdown, 1);

    // 唤醒所有等待中的 Ask 请求
    ExAcquireFastMutex(&g_State.PendingAskLock);
    for (PLIST_ENTRY e = g_State.PendingAskList.Flink; e != &g_State.PendingAskList; e = e->Flink) {
        PPENDING_ASK pending = CONTAINING_RECORD(e, PENDING_ASK, ListEntry);
        pending->Decision = (UINT32)Allow;
        InterlockedExchange(&pending->HasResponse, 1);
        KeSetEvent(&pending->ResponseEvent, IO_NO_INCREMENT, FALSE);
    }
    ExReleaseFastMutex(&g_State.PendingAskLock);

    // 无限期等待所有待处理操作完成
    LARGE_INTEGER waitSlice;
    waitSlice.QuadPart = -10000000LL; // 1秒

    for (;;) {
        LONG pendingOps = InterlockedCompareExchange(&g_State.MiniFilterPendingOps, 0, 0);
        if (pendingOps == 0) {
            Log("MiniFilterUnload: All pending operations completed.");
            break;
        }
        Log("MiniFilterUnload: Waiting for %d pending ops...", pendingOps);
        KeWaitForSingleObject(&g_State.MiniFilterNoPendingOps, Executive, KernelMode, FALSE, &waitSlice);
    }

    g_State.MiniFilterHandle = nullptr;
    Log("MiniFilterUnload: Unload completed successfully.");
    return STATUS_SUCCESS;
}

static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreate, nullptr },
    { IRP_MJ_READ, 0, PreRead, nullptr },
    { IRP_MJ_WRITE, 0, PreWrite, nullptr },
    { IRP_MJ_SET_INFORMATION, 0, PreSetInformation, nullptr },
    { IRP_MJ_SET_EA, 0, PreSetEa, nullptr },
    { IRP_MJ_SET_SECURITY, 0, PreSetSecurity, nullptr },
    { IRP_MJ_CLEANUP, 0, PreCleanup, nullptr },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    nullptr,
    Callbacks,
    MiniFilterUnload,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr
};

extern "C" NTSTATUS InitializeMiniFilter(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_State.MiniFilterHandle)
        return STATUS_SUCCESS;

    g_State.MiniFilterPendingOps = 0;
    g_State.MiniFilterShutdown = 0;
    KeInitializeEvent(&g_State.MiniFilterNoPendingOps, NotificationEvent, TRUE);

    PFLT_FILTER filter = nullptr;
    NTSTATUS status = FltRegisterFilter(DriverObject, &FilterRegistration, &filter);
    if (!NT_SUCCESS(status)) {
        Log("InitializeMiniFilter: FltRegisterFilter failed: 0x%08X", status);
        return status;
    }

    status = FltStartFiltering(filter);
    if (!NT_SUCCESS(status)) {
        Log("InitializeMiniFilter: FltStartFiltering failed: 0x%08X", status);
        FltUnregisterFilter(filter);
        return status;
    }

    g_State.MiniFilterHandle = filter;
    return status;
}

extern "C" VOID UninitializeMiniFilter()
{
    if (g_State.MiniFilterHandle) {
        // FltUnregisterFilter 会触发 MiniFilterUnload 回调
        // 等待逻辑已经在 MiniFilterUnload 中处理
        FltUnregisterFilter((PFLT_FILTER)g_State.MiniFilterHandle);
        g_State.MiniFilterHandle = nullptr;
    }
}
