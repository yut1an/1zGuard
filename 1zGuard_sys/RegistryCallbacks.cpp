#include "RegistryCallbacks.h"

extern "C" GLOBAL_STATE g_State;

extern "C" NTSTATUS NTAPI RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
);

static NTSTATUS GetKeyObjectName(
    _In_ PVOID Object,
    _Out_ UNICODE_STRING* KeyName,
    _Outptr_result_maybenull_ PCUNICODE_STRING* NameToRelease
)
{
    if (KeyName)
        RtlZeroMemory(KeyName, sizeof(*KeyName));
    if (NameToRelease)
        *NameToRelease = nullptr;

    if (!Object || !KeyName || !NameToRelease)
        return STATUS_INVALID_PARAMETER;

    PCUNICODE_STRING objectName = nullptr;
    NTSTATUS status = CmCallbackGetKeyObjectIDEx(
        &g_State.RegistryCallbackCookie,
        Object,
        nullptr,
        &objectName,
        0);
    if (!NT_SUCCESS(status) || !objectName)
        return status;

    // Copy the UNICODE_STRING content for use by matching.
    *KeyName = *objectName;

    // Keep the original pointer to release with CmCallbackReleaseKeyObjectIDEx.
    *NameToRelease = objectName;
    return STATUS_SUCCESS;
}

static VOID ReleaseKeyObjectName(_In_opt_ PCUNICODE_STRING NameToRelease)
{
    if (!NameToRelease)
        return;

    CmCallbackReleaseKeyObjectIDEx(NameToRelease);
}

static BOOLEAN BuildValueResourcePath(
    _In_ PVOID Object,
    _In_opt_ PCUNICODE_STRING ValueName,
    _Out_ UNICODE_STRING* ResourcePath,
    _Outptr_result_maybenull_ PCUNICODE_STRING* NameToRelease,
    _Outptr_result_maybenull_ PWCHAR* AllocatedPathToFree
)
{
    RtlZeroMemory(ResourcePath, sizeof(*ResourcePath));
    *NameToRelease = nullptr;
    *AllocatedPathToFree = nullptr;

    UNICODE_STRING keyPath = { 0 };
    PCUNICODE_STRING nameToRelease = nullptr;
    if (!NT_SUCCESS(GetKeyObjectName(Object, &keyPath, &nameToRelease)))
        return FALSE;

    if (!ValueName || !ValueName->Buffer || ValueName->Length == 0)
    {
        *ResourcePath = keyPath;
        *NameToRelease = nameToRelease;
        return TRUE;
    }

    USHORT keyChars = (USHORT)(keyPath.Length / sizeof(WCHAR));
    USHORT valChars = (USHORT)(ValueName->Length / sizeof(WCHAR));
    SIZE_T totalChars = (SIZE_T)keyChars + 1 + (SIZE_T)valChars;

    PWCHAR buf = (PWCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        (totalChars + 1) * sizeof(WCHAR),
        TAG_STRING
    );
    if (!buf)
    {
        CmCallbackReleaseKeyObjectIDEx(nameToRelease);
        return FALSE;
    }

    SIZE_T offsetChars = 0;
    if (keyChars)
    {
        RtlCopyMemory(buf, keyPath.Buffer, keyChars * sizeof(WCHAR));
        offsetChars += keyChars;
    }
    buf[offsetChars++] = L'\\';
    if (valChars)
    {
        RtlCopyMemory(buf + offsetChars, ValueName->Buffer, valChars * sizeof(WCHAR));
        offsetChars += valChars;
    }
    buf[offsetChars] = L'\0';

    ResourcePath->Buffer = buf;
    ResourcePath->Length = (USHORT)(offsetChars * sizeof(WCHAR));
    ResourcePath->MaximumLength = (USHORT)((offsetChars + 1) * sizeof(WCHAR));

    *AllocatedPathToFree = buf;
    *NameToRelease = nameToRelease;
    return TRUE;
}

static BOOLEAN BuildActionAndPath(
    _In_ REG_NOTIFY_CLASS regClass,
    _In_ PVOID Argument2,
    _Out_ ActionType* Action,
    _Out_ UNICODE_STRING* ResourcePath,
    _Outptr_result_maybenull_ PCUNICODE_STRING* NameToRelease,
    _Outptr_result_maybenull_ PWCHAR* AllocatedPathToFree
)
{
    RtlZeroMemory(Action, sizeof(*Action));
    RtlZeroMemory(ResourcePath, sizeof(*ResourcePath));
    *NameToRelease = nullptr;
    *AllocatedPathToFree = nullptr;

    if (!Argument2)
        return FALSE;

    switch (regClass)
    {
    case RegNtPreCreateKey:
    case RegNtPreCreateKeyEx:
    {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        if (info->CompleteName)
            *ResourcePath = *info->CompleteName;
        Action->fields.Create = 1;
        return TRUE;
    }
    case RegNtPreOpenKey:
    case RegNtPreOpenKeyEx:
    {
        PREG_OPEN_KEY_INFORMATION info = (PREG_OPEN_KEY_INFORMATION)Argument2;
        if (info->CompleteName)
            *ResourcePath = *info->CompleteName;
        Action->fields.Read = 1;
        return TRUE;
    }
    case RegNtPreDeleteKey:
    {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
        if (NT_SUCCESS(GetKeyObjectName(info->Object, ResourcePath, NameToRelease)))
        {
            Action->fields.Delete = 1;
            return TRUE;
        }
        break;
    }
    case RegNtPreSetValueKey:
    {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        Action->fields.Create = 1;
        Action->fields.Modify = 1;
        return BuildValueResourcePath(info->Object, info->ValueName, ResourcePath, NameToRelease, AllocatedPathToFree);
        break;
    }
    case RegNtPreDeleteValueKey:
    {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        Action->fields.Delete = 1;
        return BuildValueResourcePath(info->Object, info->ValueName, ResourcePath, NameToRelease, AllocatedPathToFree);
        break;
    }
    case RegNtPreQueryValueKey:
    {
        PREG_QUERY_VALUE_KEY_INFORMATION info = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
        Action->fields.Read = 1;
        return BuildValueResourcePath(info->Object, info->ValueName, ResourcePath, NameToRelease, AllocatedPathToFree);
    }
    case RegNtPreQueryKey:
    {
        PREG_QUERY_KEY_INFORMATION info = (PREG_QUERY_KEY_INFORMATION)Argument2;
        if (NT_SUCCESS(GetKeyObjectName(info->Object, ResourcePath, NameToRelease)))
        {
            Action->fields.Read = 1;
            return TRUE;
        }
        break;
    }
    case RegNtPreEnumerateKey:
    {
        PREG_ENUMERATE_KEY_INFORMATION info = (PREG_ENUMERATE_KEY_INFORMATION)Argument2;
        if (NT_SUCCESS(GetKeyObjectName(info->Object, ResourcePath, NameToRelease)))
        {
            Action->fields.Read = 1;
            return TRUE;
        }
        break;
    }
    case RegNtPreEnumerateValueKey:
    {
        PREG_ENUMERATE_VALUE_KEY_INFORMATION info = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)Argument2;
        if (NT_SUCCESS(GetKeyObjectName(info->Object, ResourcePath, NameToRelease)))
        {
            Action->fields.Read = 1;
            return TRUE;
        }
        break;
    }
    case RegNtPreQueryMultipleValueKey:
    {
        PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION info = (PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)Argument2;
        if (NT_SUCCESS(GetKeyObjectName(info->Object, ResourcePath, NameToRelease)))
        {
            Action->fields.Read = 1;
            return TRUE;
        }
        break;
    }
    case RegNtPreRenameKey:
    {
        PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
        if (NT_SUCCESS(GetKeyObjectName(info->Object, ResourcePath, NameToRelease)))
        {
            Action->fields.Modify = 1;
            return TRUE;
        }
        break;
    }
    case RegNtPreSetInformationKey:
    {
        PREG_SET_INFORMATION_KEY_INFORMATION info = (PREG_SET_INFORMATION_KEY_INFORMATION)Argument2;
        if (NT_SUCCESS(GetKeyObjectName(info->Object, ResourcePath, NameToRelease)))
        {
            Action->fields.Modify = 1;
            return TRUE;
        }
        break;
    }
    default:
        break;
    }

    return FALSE;
}

extern "C" NTSTATUS NTAPI RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    REG_NOTIFY_CLASS regClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    if (!g_State.pRuleManager)
        return STATUS_SUCCESS;

    if (InterlockedCompareExchange(&g_State.ProtectionEnabled, 0, 0) == 0)
        return STATUS_SUCCESS;

    // 客户端进程白名单：跳过客户端自己的操作
    if (IsCurrentProcessClient())
        return STATUS_SUCCESS;

    KIRQL irql = KeGetCurrentIrql();
    if (irql >= DISPATCH_LEVEL) {
        return STATUS_SUCCESS;
    }
    BOOLEAN canAsk = TRUE;

    UNICODE_STRING processName = { 0 };
    BOOLEAN hasProc = GetCurrentProcessName(&processName);

    UNICODE_STRING resourcePath = { 0 };
    PCUNICODE_STRING nameToRelease = nullptr;
    PWCHAR allocatedPathToFree = nullptr;
    ActionType action = { 0 };

    if (!BuildActionAndPath(regClass, Argument2, &action, &resourcePath, &nameToRelease, &allocatedPathToFree))
    {
        if (hasProc)
            RtlFreeUnicodeString(&processName);
        return STATUS_SUCCESS;
    }

    INT32 ruleId = -1;
    WCHAR ruleNameBuf[64] = { 0 };
    UINT8 treatmentByte = g_State.pRuleManager->MatchRegistryEx(
        hasProc ? &processName : nullptr,
        action,
        &resourcePath,
        &ruleId,
        ruleNameBuf,
        RTL_NUMBER_OF(ruleNameBuf)
    );

    Treatment treatment = (Treatment)treatmentByte;

    NTSTATUS finalStatus = STATUS_SUCCESS;

    if (treatment == Block)
    {
        finalStatus = STATUS_ACCESS_DENIED;
        goto Exit;
    }

    if (treatment == Ask && canAsk)
    {
        UNICODE_STRING ruleName;
        RtlInitUnicodeString(&ruleName, ruleNameBuf);
        Treatment decision = Allow;
        NTSTATUS status = SendAskAndWait(
            Registry,
            action,
            hasProc ? &processName : nullptr,
            nullptr,
            &resourcePath,
            ruleId,
            &ruleName,
            30,
            &decision
        );

        if (!NT_SUCCESS(status) || decision == Block)
            finalStatus = STATUS_ACCESS_DENIED;
        goto Exit;
    }

Exit:
    if (allocatedPathToFree)
        ExFreePool(allocatedPathToFree);
    ReleaseKeyObjectName(nameToRelease);

    if (hasProc)
        RtlFreeUnicodeString(&processName);

    return finalStatus;
}

extern "C" NTSTATUS InitializeRegistryCallback(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"300001");
    NTSTATUS status = CmRegisterCallbackEx(RegistryCallback,
                                           &altitude,
                                           DriverObject,
                                           nullptr,
                                           &g_State.RegistryCallbackCookie,
                                           nullptr);
    if (!NT_SUCCESS(status))
    {
        g_State.RegistryCallbackCookie.QuadPart = 0;
    }

    return status;
}

extern "C" VOID UninitializeRegistryCallback()
{
    if (g_State.RegistryCallbackCookie.QuadPart != 0)
    {
        CmUnRegisterCallback(g_State.RegistryCallbackCookie);
        g_State.RegistryCallbackCookie.QuadPart = 0;
    }
}
