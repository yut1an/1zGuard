#include "Common.h"

extern "C" GLOBAL_STATE g_State;

// 将 NT 路径转换为 DOS 路径（不依赖 FLT_VOLUME）
static BOOLEAN ConvertNtPathToDosPath(
    _In_ PCUNICODE_STRING NtPath,
    _Out_ PUNICODE_STRING DosPath)
{
    RtlZeroMemory(DosPath, sizeof(*DosPath));
    if (!NtPath || !NtPath->Buffer || NtPath->Length < sizeof(WCHAR))
        return FALSE;

    // 检查是否以 \Device\ 开头
    static const WCHAR kDevicePrefix[] = L"\\Device\\";
    UNICODE_STRING devicePrefix;
    RtlInitUnicodeString(&devicePrefix, kDevicePrefix);
    if (!RtlPrefixUnicodeString(&devicePrefix, NtPath, TRUE))
        return FALSE;

    // 找到第三个反斜杠的位置（\Device\HarddiskVolumeX\...）
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

    // 提取设备名称部分
    UNICODE_STRING deviceName;
    deviceName.Buffer = NtPath->Buffer;
    deviceName.Length = (USHORT)(remainderIndex * sizeof(WCHAR));
    deviceName.MaximumLength = deviceName.Length;

    // 查找对应的盘符
    WCHAR driveLetter = L'\0';
    for (WCHAR letter = L'A'; letter <= L'Z'; letter++) {
        WCHAR linkName[16];
        linkName[0] = L'\\';
        linkName[1] = L'?';
        linkName[2] = L'?';
        linkName[3] = L'\\';
        linkName[4] = letter;
        linkName[5] = L':';
        linkName[6] = L'\0';

        UNICODE_STRING linkNameStr;
        RtlInitUnicodeString(&linkNameStr, linkName);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &linkNameStr, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        HANDLE linkHandle = nullptr;
        NTSTATUS status = ZwOpenSymbolicLinkObject(&linkHandle, GENERIC_READ, &oa);
        if (!NT_SUCCESS(status))
            continue;

        WCHAR targetBuf[260];
        UNICODE_STRING targetStr;
        targetStr.Buffer = targetBuf;
        targetStr.Length = 0;
        targetStr.MaximumLength = sizeof(targetBuf);

        ULONG returnedLength = 0;
        status = ZwQuerySymbolicLinkObject(linkHandle, &targetStr, &returnedLength);
        ZwClose(linkHandle);

        if (NT_SUCCESS(status) && targetStr.Length > 0) {
            if (RtlEqualUnicodeString(&targetStr, &deviceName, TRUE)) {
                driveLetter = letter;
                break;
            }
        }
    }

    if (driveLetter == L'\0')
        return FALSE;

    // 构建 DOS 路径：C:\...
    USHORT remainderOffsetBytes = (USHORT)(remainderIndex * sizeof(WCHAR));
    USHORT remainderLenBytes = (USHORT)(NtPath->Length - remainderOffsetBytes);
    USHORT outLenBytes = (USHORT)(2 * sizeof(WCHAR) + remainderLenBytes); // "C:" + remainder

    PWCHAR outBuf = (PWCHAR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        (SIZE_T)outLenBytes + sizeof(WCHAR),
        TAG_STRING);

    if (!outBuf)
        return FALSE;

    outBuf[0] = driveLetter;
    outBuf[1] = L':';
    RtlCopyMemory(&outBuf[2], &NtPath->Buffer[remainderIndex], remainderLenBytes);
    outBuf[(outLenBytes / sizeof(WCHAR))] = L'\0';

    DosPath->Buffer = outBuf;
    DosPath->Length = outLenBytes;
    DosPath->MaximumLength = outLenBytes + sizeof(WCHAR);

    return TRUE;
}

BOOLEAN GetCurrentProcessName(_Out_ PUNICODE_STRING ProcessName)
{
    if (!ProcessName)
        return FALSE;

    RtlZeroMemory(ProcessName, sizeof(*ProcessName));

    PEPROCESS process = PsGetCurrentProcess();
    if (!process)
        return FALSE;

    PUNICODE_STRING imagePath = nullptr;
    NTSTATUS status = SeLocateProcessImageName(process, &imagePath);
    if (!NT_SUCCESS(status) || !imagePath || !imagePath->Buffer || imagePath->Length == 0) {
        if (imagePath)
            ExFreePool(imagePath);
        return FALSE;
    }

    status = RtlDuplicateUnicodeString(
        RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
        imagePath,
        ProcessName);

    ExFreePool(imagePath);
    return NT_SUCCESS(status);
}

BOOLEAN IsCurrentProcessClient()
{
    // 必须在 PASSIVE_LEVEL 调用（因为需要访问符号链接）
    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return FALSE;

    // 如果没有注册客户端路径，返回 FALSE
    KIRQL irql;
    KeAcquireSpinLock(&g_State.ClientPathLock, &irql);
    if (g_State.ClientProcessPath[0] == L'\0') {
        KeReleaseSpinLock(&g_State.ClientPathLock, irql);
        return FALSE;
    }

    // 复制客户端路径到本地缓冲区
    WCHAR clientPath[520];
    RtlCopyMemory(clientPath, g_State.ClientProcessPath, sizeof(clientPath));
    KeReleaseSpinLock(&g_State.ClientPathLock, irql);

    // 获取当前进程路径（NT 格式）
    UNICODE_STRING currentNtPath;
    if (!GetCurrentProcessName(&currentNtPath)) {
        return FALSE;
    }

    // 将 NT 路径转换为 DOS 路径
    UNICODE_STRING currentDosPath;
    if (!ConvertNtPathToDosPath(&currentNtPath, &currentDosPath)) {
        RtlFreeUnicodeString(&currentNtPath);
        return FALSE;
    }
    RtlFreeUnicodeString(&currentNtPath);

    // 比较路径（不区分大小写）
    UNICODE_STRING clientPathStr;
    RtlInitUnicodeString(&clientPathStr, clientPath);

    BOOLEAN isClient = RtlEqualUnicodeString(&currentDosPath, &clientPathStr, TRUE);

    // 释放 DOS 路径（由 ExAllocatePool2 分配）
    if (currentDosPath.Buffer) {
        ExFreePoolWithTag(currentDosPath.Buffer, TAG_STRING);
    }

    return isClient;
}
