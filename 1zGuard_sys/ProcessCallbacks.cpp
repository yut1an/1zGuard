#include "ProcessCallbacks.h"

extern "C" GLOBAL_STATE g_State;

// 前向声明 CSQ 相关函数
extern PCSQ_IRP_CONTEXT GetIrpCsqContext(_In_ PIRP Irp);
extern VOID SetIrpCsqContext(_In_ PIRP Irp, _In_opt_ PCSQ_IRP_CONTEXT Ctx);

// 特殊结束标记：request_id = 0xFFFFFFFF 表示监听线程应退出
#define ASK_REQUEST_ID_SHUTDOWN 0xFFFFFFFF

// 客户端进程退出时的清理函数
static VOID OnClientProcessExit(_In_ HANDLE ProcessId)
{
    Log("OnClientProcessExit: Client process %p is exiting, performing cleanup...", ProcessId);

    // 1. 立即禁用保护
    InterlockedExchange(&g_State.ProtectionEnabled, 0);
    Log("OnClientProcessExit: Protection disabled");

    // 2. 唤醒所有等待中的 Ask 请求，设置为 Block
    ExAcquireFastMutex(&g_State.PendingAskLock);
    for (PLIST_ENTRY e = g_State.PendingAskList.Flink; e != &g_State.PendingAskList; e = e->Flink) {
        PPENDING_ASK pending = CONTAINING_RECORD(e, PENDING_ASK, ListEntry);
        pending->Decision = (UINT32)Block;
        InterlockedExchange(&pending->HasResponse, 1);
        KeSetEvent(&pending->ResponseEvent, IO_NO_INCREMENT, FALSE);
    }
    ExReleaseFastMutex(&g_State.PendingAskLock);
    Log("OnClientProcessExit: All pending ask requests rejected");

    // 3. 完成所有 pending 的 IOCTL_GET_NEXT_ASK IRP，发送结束标记
    for (;;) {
        PIRP irp = IoCsqRemoveNextIrp(&g_State.CsqQueue, nullptr);
        if (!irp)
            break;

        // 清理 IRP 上下文
        PCSQ_IRP_CONTEXT ctx = GetIrpCsqContext(irp);
        if (ctx) {
            SetIrpCsqContext(irp, nullptr);
            ExFreePool(ctx);
        }

        // 填充结束标记响应
        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
        ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
        
        if (outputLength >= sizeof(USER_ASK_REQUEST)) {
            USER_ASK_REQUEST* outReq = (USER_ASK_REQUEST*)irp->AssociatedIrp.SystemBuffer;
            RtlZeroMemory(outReq, sizeof(USER_ASK_REQUEST));
            outReq->RequestId = ASK_REQUEST_ID_SHUTDOWN;  // 特殊结束标记
            outReq->TimeoutSeconds = 0;
            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = sizeof(USER_ASK_REQUEST);
            Log("OnClientProcessExit: Sent shutdown marker to pending IRP");
        } else {
            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = 0;
        }

        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
    Log("OnClientProcessExit: All pending IRPs completed with shutdown marker");

    // 4. 清空客户端进程路径和ID
    KIRQL irql;
    KeAcquireSpinLock(&g_State.ClientPathLock, &irql);
    RtlZeroMemory(g_State.ClientProcessPath, sizeof(g_State.ClientProcessPath));
    KeReleaseSpinLock(&g_State.ClientPathLock, irql);

    KeAcquireSpinLock(&g_State.MainProcessIdLock, &irql);
    g_State.MainProcessId = nullptr;
    KeReleaseSpinLock(&g_State.MainProcessIdLock, irql);

    Log("OnClientProcessExit: Cleanup completed");
}

static VOID NTAPI ProcessNotifyEx(
    _Inout_ PEPROCESS ProcessObj,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(ProcessObj);

    // 进程退出检测：检查是否是客户端主进程退出
    if (!CreateInfo) {
        // CreateInfo == NULL 表示进程退出
        KIRQL irql;
        HANDLE mainPid = nullptr;
        
        KeAcquireSpinLock(&g_State.MainProcessIdLock, &irql);
        mainPid = g_State.MainProcessId;
        KeReleaseSpinLock(&g_State.MainProcessIdLock, irql);
        
        if (mainPid != nullptr && ProcessId == mainPid) {
            // 客户端主进程退出，执行清理
            OnClientProcessExit(ProcessId);
        }
        return;
    }

    if (!g_State.pRuleManager)
        return;

    if (InterlockedCompareExchange(&g_State.ProtectionEnabled, 0, 0) == 0)
        return;

    // 客户端进程白名单：跳过客户端自己的操作
    if (IsCurrentProcessClient())
        return;

    if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
        return;

    if (CreateInfo->IsSubsystemProcess)
        return;

    if (!CreateInfo->ImageFileName || !CreateInfo->ImageFileName->Buffer || CreateInfo->ImageFileName->Length == 0)
        return;

    UNICODE_STRING parentProc = { 0 };
    BOOLEAN hasParent = GetCurrentProcessName(&parentProc);

    UNICODE_STRING childImageDup = { 0 };
    UNICODE_STRING cmdLineDup = { 0 };
    UNICODE_STRING args = { 0 };

    ActionType action = { 0 };
    action.fields.Execute = 1;

    NTSTATUS dupStatus = RtlDuplicateUnicodeString(
        RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
        CreateInfo->ImageFileName,
        &childImageDup);
    if (!NT_SUCCESS(dupStatus) || !childImageDup.Buffer) {
        goto Exit;
    }


    if (CreateInfo->CommandLine && CreateInfo->CommandLine->Buffer && CreateInfo->CommandLine->Length) {
        dupStatus = RtlDuplicateUnicodeString(
            RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
            CreateInfo->CommandLine,
            &cmdLineDup);
        if (!NT_SUCCESS(dupStatus)) {
            RtlFreeUnicodeString(&childImageDup);
            goto Exit;
        }
    }

    if (cmdLineDup.Buffer) {
        PCWSTR b = cmdLineDup.Buffer;
        SIZE_T cch = cmdLineDup.Length / sizeof(WCHAR);

        SIZE_T i = 0;
        while (i < cch && (b[i] == L' ' || b[i] == L'\t'))
            i++;

        if (i < cch && b[i] == L'"') {
            i++;
            while (i < cch && b[i] != L'"')
                i++;
            if (i < cch && b[i] == L'"')
                i++;
        }
        else {
            while (i < cch && b[i] != L' ' && b[i] != L'\t')
                i++;
        }

        while (i < cch && (b[i] == L' ' || b[i] == L'\t'))
            i++;

        if (i < cch) {
            args.Buffer = (PWSTR)(b + i);
            args.Length = (USHORT)((cch - i) * sizeof(WCHAR));
            args.MaximumLength = args.Length;
        }
    }

    const UNICODE_STRING* childImage = &childImageDup;

    INT32 ruleId = -1;
    WCHAR ruleNameBuf[64] = { 0 };
    UINT8 treatmentByte = g_State.pRuleManager->MatchProcessEx(
        hasParent ? &parentProc : nullptr,
        action,
        childImage,
        (args.Buffer ? &args : nullptr),
        &ruleId,
        ruleNameBuf,
        RTL_NUMBER_OF(ruleNameBuf)
    );

    Treatment treatment = (Treatment)treatmentByte;

    if (treatment == Block) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        goto Exit;
    }

    if (treatment == Ask) {
        UNICODE_STRING ruleName;
        RtlInitUnicodeString(&ruleName, ruleNameBuf);

        const UNICODE_STRING* displayTarget = cmdLineDup.Buffer ? &cmdLineDup : childImage;

        Treatment decision = Allow;
        NTSTATUS status = SendAskAndWait(
            Process,
            action,
            hasParent ? &parentProc : nullptr,
            nullptr,
            displayTarget,
            ruleId,
            &ruleName,
            30,
            &decision
        );

        if (!NT_SUCCESS(status) || decision == Block) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        }
    }

Exit:
    if (cmdLineDup.Buffer)
        RtlFreeUnicodeString(&cmdLineDup);
    if (childImageDup.Buffer)
        RtlFreeUnicodeString(&childImageDup);
    if (hasParent)
        RtlFreeUnicodeString(&parentProc);

    return;
}

extern "C" NTSTATUS InitializeProcessCallback(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx2(
        PsCreateProcessNotifySubsystems,
        (PVOID)ProcessNotifyEx,
        FALSE
    );

    if (!NT_SUCCESS(status)) {
        Log("InitializeProcessCallback failed: 0x%08X", status);
    }

    return status;
}

extern "C" VOID UninitializeProcessCallback()
{
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx2(
        PsCreateProcessNotifySubsystems,
        (PVOID)ProcessNotifyEx,
        TRUE
    );

    if (!NT_SUCCESS(status)) {
        Log("UninitializeProcessCallback failed: 0x%08X", status);
    }
}
