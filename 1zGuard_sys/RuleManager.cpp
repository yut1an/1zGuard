#include "Common.h"
#include "RuleManager.h"
#include <ntstrsafe.h>

NTSTATUS RuleManager::Initialize() {
    if (m_initialized) {
        return STATUS_SUCCESS;
    }

    InitializeListHead(&m_rule_list);
    ExInitializePushLock(&m_lock);
    m_rule_count = 0;
    m_rule_lookaside = nullptr;
    m_policy_lookaside = nullptr;

    Log("RuleManager::Initialize enter this=%p", this);

    m_rule_lookaside = (PNPAGED_LOOKASIDE_LIST)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(NPAGED_LOOKASIDE_LIST),
        TAG_RULE);
    if (!m_rule_lookaside) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Log("RuleManager::Initialize m_rule_lookaside=%p", m_rule_lookaside);

    ExInitializeNPagedLookasideList(
        m_rule_lookaside,
        nullptr,
        nullptr,
        0,
        sizeof(RuleItem),
        TAG_RULE,
        0
    );

    m_policy_lookaside = (PNPAGED_LOOKASIDE_LIST)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(NPAGED_LOOKASIDE_LIST),
        TAG_POLICY);
    if (!m_policy_lookaside) {
        ExDeleteNPagedLookasideList(m_rule_lookaside);
        ExFreePoolWithTag(m_rule_lookaside, TAG_RULE);
        m_rule_lookaside = nullptr;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExInitializeNPagedLookasideList(
        m_policy_lookaside,
        nullptr,
        nullptr,
        0,
        sizeof(Policy),
        TAG_POLICY,
        0
    );

    m_initialized = TRUE;
    Log("RuleManager initialization successful!");
    return STATUS_SUCCESS;
}

void RuleManager::Uninitialize() {
    if (!m_initialized) {
        return;
    }

    ExAcquirePushLockExclusiveEx(&m_lock, 0);
    ClearAllNoLock();
    ExReleasePushLockExclusiveEx(&m_lock, 0);

    if (m_rule_lookaside) {
        ExDeleteNPagedLookasideList(m_rule_lookaside);
        ExFreePoolWithTag(m_rule_lookaside, TAG_RULE);
        m_rule_lookaside = nullptr;
    }

    if (m_policy_lookaside) {
        ExDeleteNPagedLookasideList(m_policy_lookaside);
        ExFreePoolWithTag(m_policy_lookaside, TAG_POLICY);
        m_policy_lookaside = nullptr;
    }

    m_initialized = FALSE;
    Log("RuleManager Uninitialize!");
}

// ...

UINT8  RuleManager::MatchInternal(PCUNICODE_STRING processName, ActionType action, PCUNICODE_STRING resourcePath, ProtectType type) const {
    UNREFERENCED_PARAMETER(processName);
    UNREFERENCED_PARAMETER(resourcePath);
    if (!m_initialized) {
        return Allow;
    }

    ExAcquirePushLockSharedEx(&m_lock, 0);

    UINT8 result = Allow;
    PLIST_ENTRY entry = m_rule_list.Flink;

    while (entry != &m_rule_list) {
        RuleItem* rule = CONTAINING_RECORD(entry, RuleItem, ListEntry);
        entry = entry->Flink;

        if (!rule->power) {
            continue;
        }

        if (rule->procname && rule->procname[0] != L'\0') {
            UNICODE_STRING procPattern;
            RtlInitUnicodeString(&procPattern, rule->procname);

            if (wcscmp(rule->procname, L"*") != 0) {
                if (!WildcardMatch(&procPattern, processName)) {
                    if (processName && processName->Buffer) {
                        PCWSTR b = processName->Buffer;
                        PCWSTR last = b;
                        for (PCWSTR p = b; *p; ++p) {
                            if (*p == L'\\')
                                last = p + 1;
                        }
                        UNICODE_STRING base;
                        RtlInitUnicodeString(&base, last);
                        if (!WildcardMatch(&procPattern, &base)) {
                            continue;
                        }
                    }
                    else {
                        continue;
                    }
                }
            }
        }

        Policy* policies = nullptr;
        UINT32 count = 0;

        switch (type) {
        case Process:
            policies = rule->process_policies;
            count = rule->process_count;
            break;
        case File:
            policies = rule->file_policies;
            count = rule->file_count;
            break;
        case Registry:
            policies = rule->registry_policies;
            count = rule->registry_count;
            break;
        }

        if (!policies || count == 0) {
            continue;
        }

        for (UINT32 i = 0; i < count; i++) {
            Policy* policy = &policies[i];

            if (policy->res_path && policy->res_path[0] != L'\0') {
                UNICODE_STRING pathPattern;
                RtlInitUnicodeString(&pathPattern, policy->res_path);
                if (!WildcardMatch(&pathPattern, resourcePath)) {
                    continue;
                }
            }

            // 检查操作类型是否匹配
            if ((policy->action_type.all & action.all) == 0) {
                continue;
            }

            // 匹配成功，返回处理方式
            result = (UINT8)rule->treatment;
            goto Exit;
        }
    }
Exit:
    ExReleasePushLockSharedEx(&m_lock, 0);
    return result;
}

UINT8 RuleManager::MatchRegistry(
    PCUNICODE_STRING processName,
    ActionType action,
    PCUNICODE_STRING keyPath) const {
    return MatchInternal(processName, action, keyPath, Registry);
}

UINT8 RuleManager::MatchRegistryEx(
    _In_opt_ PCUNICODE_STRING processName,
    _In_ ActionType action,
    _In_ PCUNICODE_STRING keyPath,
    _Out_opt_ INT32* ruleId,
    _Out_writes_(ruleNameCch) PWCHAR ruleName,
    _In_ ULONG ruleNameCch) const
{
    if (ruleId)
        *ruleId = -1;
    if (ruleName && ruleNameCch)
        ruleName[0] = L'\0';

    if (!m_initialized) {
        return Allow;
    }

    ExAcquirePushLockSharedEx(&m_lock, 0);

    UINT8 result = Allow;
    PLIST_ENTRY entry = m_rule_list.Flink;

    while (entry != &m_rule_list) {
        RuleItem* rule = CONTAINING_RECORD(entry, RuleItem, ListEntry);
        entry = entry->Flink;

        if (!rule->power) {
            continue;
        }

        if (rule->procname && rule->procname[0] != L'\0') {
            UNICODE_STRING procPattern;
            RtlInitUnicodeString(&procPattern, rule->procname);

            if (wcscmp(rule->procname, L"*") != 0) {
                if (!WildcardMatch(&procPattern, processName)) {
                    if (processName && processName->Buffer) {
                        PCWSTR b = processName->Buffer;
                        PCWSTR last = b;
                        for (PCWSTR p = b; *p; ++p) {
                            if (*p == L'\\')
                                last = p + 1;
                        }
                        UNICODE_STRING base;
                        RtlInitUnicodeString(&base, last);
                        if (!WildcardMatch(&procPattern, &base)) {
                            continue;
                        }
                    }
                    else {
                        continue;
                    }
                }
            }
        }

        Policy* policies = rule->registry_policies;
        UINT32 count = rule->registry_count;
        if (!policies || count == 0) {
            continue;
        }

        for (UINT32 i = 0; i < count; i++) {
            Policy* policy = &policies[i];

            if (policy->res_path && policy->res_path[0] != L'\0') {
                UNICODE_STRING pathPattern;
                RtlInitUnicodeString(&pathPattern, policy->res_path);

                if (!WildcardMatch(&pathPattern, keyPath)) {
                    WCHAR altBuf[1024] = { 0 };
                    PCWSTR pat = policy->res_path;
                    UNICODE_STRING patStr;
                    RtlInitUnicodeString(&patStr, pat);

                    UNICODE_STRING p1 = RTL_CONSTANT_STRING(L"HKLM\\");
                    UNICODE_STRING p2 = RTL_CONSTANT_STRING(L"HKCU\\");
                    UNICODE_STRING p3 = RTL_CONSTANT_STRING(L"HKU\\");
                    UNICODE_STRING p7 = RTL_CONSTANT_STRING(L"HKCR\\");
                    UNICODE_STRING p9 = RTL_CONSTANT_STRING(L"HKCC\\");
                    UNICODE_STRING p4 = RTL_CONSTANT_STRING(L"HKEY_LOCAL_MACHINE\\");
                    UNICODE_STRING p5 = RTL_CONSTANT_STRING(L"HKEY_CURRENT_USER\\");
                    UNICODE_STRING p6 = RTL_CONSTANT_STRING(L"HKEY_USERS\\");
                    UNICODE_STRING p8 = RTL_CONSTANT_STRING(L"HKEY_CLASSES_ROOT\\");
                    UNICODE_STRING p10 = RTL_CONSTANT_STRING(L"HKEY_CURRENT_CONFIG\\");

                    if (RtlPrefixUnicodeString(&p1, &patStr, TRUE) || RtlPrefixUnicodeString(&p4, &patStr, TRUE)) {
                        SIZE_T skip = RtlPrefixUnicodeString(&p1, &patStr, TRUE) ? 5 : 19;
                        RtlStringCchCopyW(altBuf, RTL_NUMBER_OF(altBuf), L"\\REGISTRY\\MACHINE\\");
                        RtlStringCchCatW(altBuf, RTL_NUMBER_OF(altBuf), pat + skip);
                        UNICODE_STRING alt;
                        RtlInitUnicodeString(&alt, altBuf);
                        if (!WildcardMatch(&alt, keyPath))
                            continue;
                    }
                    else if (RtlPrefixUnicodeString(&p2, &patStr, TRUE) || RtlPrefixUnicodeString(&p5, &patStr, TRUE)) {
                        SIZE_T skip = RtlPrefixUnicodeString(&p2, &patStr, TRUE) ? 5 : 18;
                        RtlStringCchCopyW(altBuf, RTL_NUMBER_OF(altBuf), L"\\REGISTRY\\USER\\*\\");
                        RtlStringCchCatW(altBuf, RTL_NUMBER_OF(altBuf), pat + skip);
                        UNICODE_STRING alt;
                        RtlInitUnicodeString(&alt, altBuf);
                        if (!WildcardMatch(&alt, keyPath))
                            continue;
                    }
                    else if (RtlPrefixUnicodeString(&p3, &patStr, TRUE) || RtlPrefixUnicodeString(&p6, &patStr, TRUE)) {
                        SIZE_T skip = RtlPrefixUnicodeString(&p3, &patStr, TRUE) ? 4 : 11;
                        RtlStringCchCopyW(altBuf, RTL_NUMBER_OF(altBuf), L"\\REGISTRY\\USER\\");
                        RtlStringCchCatW(altBuf, RTL_NUMBER_OF(altBuf), pat + skip);
                        UNICODE_STRING alt;
                        RtlInitUnicodeString(&alt, altBuf);
                        if (!WildcardMatch(&alt, keyPath))
                            continue;
                    }
                    else if (RtlPrefixUnicodeString(&p7, &patStr, TRUE) || RtlPrefixUnicodeString(&p8, &patStr, TRUE)) {
                        SIZE_T skip = RtlPrefixUnicodeString(&p7, &patStr, TRUE) ? 5 : 18;

                        RtlStringCchCopyW(altBuf, RTL_NUMBER_OF(altBuf), L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\");
                        RtlStringCchCatW(altBuf, RTL_NUMBER_OF(altBuf), pat + skip);
                        UNICODE_STRING alt;
                        RtlInitUnicodeString(&alt, altBuf);
                        if (!WildcardMatch(&alt, keyPath)) {
                            RtlStringCchCopyW(altBuf, RTL_NUMBER_OF(altBuf), L"\\REGISTRY\\USER\\*\\Software\\Classes\\");
                            RtlStringCchCatW(altBuf, RTL_NUMBER_OF(altBuf), pat + skip);
                            RtlInitUnicodeString(&alt, altBuf);
                            if (!WildcardMatch(&alt, keyPath))
                                continue;
                        }
                    }
                    else if (RtlPrefixUnicodeString(&p9, &patStr, TRUE) || RtlPrefixUnicodeString(&p10, &patStr, TRUE)) {
                        SIZE_T skip = RtlPrefixUnicodeString(&p9, &patStr, TRUE) ? 5 : 20;

                        RtlStringCchCopyW(altBuf, RTL_NUMBER_OF(altBuf), L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current\\");
                        RtlStringCchCatW(altBuf, RTL_NUMBER_OF(altBuf), pat + skip);
                        UNICODE_STRING alt;
                        RtlInitUnicodeString(&alt, altBuf);
                        if (!WildcardMatch(&alt, keyPath))
                            continue;
                    }
                }
            }

            if ((policy->action_type.all & action.all) == 0) {
                continue;
            }

            result = (UINT8)rule->treatment;
            if (ruleId)
                *ruleId = rule->id;
            if (ruleName && ruleNameCch && rule->name)
                RtlStringCchCopyNW(ruleName, ruleNameCch, rule->name, ruleNameCch - 1);
            goto ExitRegistryEx;
        }
    }

ExitRegistryEx:
    ExReleasePushLockSharedEx(&m_lock, 0);
    return result;
}

UINT8 RuleManager::MatchFile(
    PCUNICODE_STRING processName,
    ActionType action,
    PCUNICODE_STRING filePath) const {
    return MatchInternal(processName, action, filePath, File);
}

UINT8 RuleManager::MatchFileEx(
    _In_opt_ PCUNICODE_STRING processName,
    _In_ ActionType action,
    _In_ PCUNICODE_STRING filePath,
    _Out_opt_ INT32* ruleId,
    _Out_writes_(ruleNameCch) PWCHAR ruleName,
    _In_ ULONG ruleNameCch) const {
    if (ruleId)
        *ruleId = -1;
    if (ruleName && ruleNameCch)
        ruleName[0] = L'\0';

    if (!m_initialized) {
        return Allow;
    }

    ExAcquirePushLockSharedEx(&m_lock, 0);

    UINT8 result = Allow;
    PLIST_ENTRY entry = m_rule_list.Flink;

    while (entry != &m_rule_list) {
        RuleItem* rule = CONTAINING_RECORD(entry, RuleItem, ListEntry);
        entry = entry->Flink;

        if (!rule->power) {
            continue;
        }

        if (rule->procname && rule->procname[0] != L'\0') {
            UNICODE_STRING procPattern;
            RtlInitUnicodeString(&procPattern, rule->procname);

            if (wcscmp(rule->procname, L"*") != 0) {
                if (!WildcardMatch(&procPattern, processName)) {
                    if (processName && processName->Buffer) {
                        PCWSTR b = processName->Buffer;
                        PCWSTR last = b;
                        for (PCWSTR p = b; *p; ++p) {
                            if (*p == L'\\')
                                last = p + 1;
                        }
                        UNICODE_STRING base;
                        RtlInitUnicodeString(&base, last);
                        if (!WildcardMatch(&procPattern, &base)) {
                            continue;
                        }
                    }
                    else {
                        continue;
                    }
                }
            }
        }

        Policy* policies = rule->file_policies;
        UINT32 count = rule->file_count;
        if (!policies || count == 0) {
            continue;
        }

        for (UINT32 i = 0; i < count; i++) {
            Policy* policy = &policies[i];

            if (policy->res_path && policy->res_path[0] != L'\0') {
                UNICODE_STRING pathPattern;
                RtlInitUnicodeString(&pathPattern, policy->res_path);
                if (!WildcardMatch(&pathPattern, filePath)) {
                    continue;
                }
            }

            if ((policy->action_type.all & action.all) == 0) {
                continue;
            }

            result = (UINT8)rule->treatment;
            if (ruleId)
                *ruleId = rule->id;
            if (ruleName && ruleNameCch && rule->name)
                RtlStringCchCopyNW(ruleName, ruleNameCch, rule->name, ruleNameCch - 1);
            goto ExitFileEx;
        }
    }

ExitFileEx:
    ExReleasePushLockSharedEx(&m_lock, 0);
    return result;
}

UINT8 RuleManager::MatchProcess(
    PCUNICODE_STRING processName,
    ActionType action,
    PCUNICODE_STRING imagePath,
    PCUNICODE_STRING cmdline) const {
    if (!m_initialized) {
        return Allow;
    }

    ExAcquirePushLockSharedEx(&m_lock, 0);

    UINT8 result = Allow;
    PLIST_ENTRY entry = m_rule_list.Flink;

    while (entry != &m_rule_list) {
        RuleItem* rule = CONTAINING_RECORD(entry, RuleItem, ListEntry);
        entry = entry->Flink;

        if (!rule->power) {
            continue;
        }

        if (rule->procname && rule->procname[0] != L'\0') {
            UNICODE_STRING procPattern;
            RtlInitUnicodeString(&procPattern, rule->procname);

            if (wcscmp(rule->procname, L"*") != 0) {
                if (!WildcardMatch(&procPattern, processName)) {
                    if (processName && processName->Buffer) {
                        PCWSTR b = processName->Buffer;
                        PCWSTR last = b;
                        for (PCWSTR p = b; *p; ++p) {
                            if (*p == L'\\')
                                last = p + 1;
                        }
                        UNICODE_STRING base;
                        RtlInitUnicodeString(&base, last);
                        if (!WildcardMatch(&procPattern, &base)) {
                            continue;
                        }
                    }
                    else {
                        continue;
                    }
                }
            }
        }

        if (!rule->process_policies || rule->process_count == 0) {
            continue;
        }

        for (UINT32 i = 0; i < rule->process_count; i++) {
            Policy* policy = &rule->process_policies[i];

            if ((policy->action_type.all & action.all) == 0) {
                continue;
            }

            if (policy->res_path && policy->res_path[0] != L'\0') {
                UNICODE_STRING pathPattern;
                RtlInitUnicodeString(&pathPattern, policy->res_path);
                if (!WildcardMatch(&pathPattern, imagePath)) {
                    continue;
                }
            }

            if (policy->res_cmdline && policy->res_cmdline[0] != L'\0') {
                if (!cmdline || !cmdline->Buffer) {
                    continue;
                }
                UNICODE_STRING cmdPattern;
                RtlInitUnicodeString(&cmdPattern, policy->res_cmdline);
                if (!WildcardMatch(&cmdPattern, cmdline)) {
                    continue;
                }
            }

            result = (UINT8)rule->treatment;
            goto ExitProcess;
        }
    }

ExitProcess:
    ExReleasePushLockSharedEx(&m_lock, 0);
    return result;
}

UINT8 RuleManager::MatchProcessEx(
    _In_opt_ PCUNICODE_STRING parentProcessName,
    _In_ ActionType action,
    _In_ PCUNICODE_STRING childImagePath,
    _In_opt_ PCUNICODE_STRING childArgs,
    _Out_opt_ INT32* ruleId,
    _Out_writes_(ruleNameCch) PWCHAR ruleName,
    _In_ ULONG ruleNameCch) const {
    if (ruleId)
        *ruleId = -1;
    if (ruleName && ruleNameCch)
        ruleName[0] = L'\0';

    if (!m_initialized) {
        return Allow;
    }

    ExAcquirePushLockSharedEx(&m_lock, 0);

    UINT8 result = Allow;
    PLIST_ENTRY entry = m_rule_list.Flink;

    while (entry != &m_rule_list) {
        RuleItem* rule = CONTAINING_RECORD(entry, RuleItem, ListEntry);
        entry = entry->Flink;

        if (!rule->power) {
            continue;
        }

        if (!rule->process_policies || rule->process_count == 0) {
            continue;
        }

        for (UINT32 i = 0; i < rule->process_count; i++) {
            Policy* policy = &rule->process_policies[i];

            // 1) action
            if ((policy->action_type.all & action.all) == 0) {
                continue;
            }

            // 2) child image path
            if (policy->res_path && policy->res_path[0] != L'\0') {
                UNICODE_STRING pathPattern;
                RtlInitUnicodeString(&pathPattern, policy->res_path);
                if (!WildcardMatch(&pathPattern, childImagePath)) {
                    continue;
                }
            }

            // 3) args ("*" matches empty args)
            if (policy->res_cmdline && policy->res_cmdline[0] != L'\0') {
                UNICODE_STRING cmdPattern;
                RtlInitUnicodeString(&cmdPattern, policy->res_cmdline);

                if (!(cmdPattern.Length == sizeof(WCHAR) && cmdPattern.Buffer[0] == L'*')) {
                    if (!childArgs || !childArgs->Buffer) {
                        continue;
                    }
                    if (!WildcardMatch(&cmdPattern, childArgs)) {
                        continue;
                    }
                }
            }

            // 4) parent process name
            if (rule->procname && rule->procname[0] != L'\0') {
                UNICODE_STRING procPattern;
                RtlInitUnicodeString(&procPattern, rule->procname);

                if (wcscmp(rule->procname, L"*") != 0) {
                    if (!WildcardMatch(&procPattern, parentProcessName)) {
                        if (parentProcessName && parentProcessName->Buffer) {
                            PCWSTR b = parentProcessName->Buffer;
                            PCWSTR last = b;
                            for (PCWSTR p = b; *p; ++p) {
                                if (*p == L'\\')
                                    last = p + 1;
                            }
                            UNICODE_STRING base;
                            RtlInitUnicodeString(&base, last);
                            if (!WildcardMatch(&procPattern, &base)) {
                                continue;
                            }
                        }
                        else {
                            continue;
                        }
                    }
                }
            }

            result = (UINT8)rule->treatment;
            if (ruleId)
                *ruleId = rule->id;
            if (ruleName && ruleNameCch && rule->name)
                RtlStringCchCopyNW(ruleName, ruleNameCch, rule->name, ruleNameCch - 1);
            break;
        }
    }

    ExReleasePushLockSharedEx(&m_lock, 0);
    return result;
}

NTSTATUS RuleManager::UpdateRule(INT32 id, const RuleItem* newRule) {
    if (!newRule)
        return STATUS_INVALID_PARAMETER;

    ExAcquirePushLockExclusiveEx(&m_lock, 0);
    NTSTATUS status = UpdateRuleNoLock(id, newRule);
    ExReleasePushLockExclusiveEx(&m_lock, 0);
    return status;
}

NTSTATUS RuleManager::UpdateRuleNoLock(INT32 id, const RuleItem* newRule)
{
    UNREFERENCED_PARAMETER(id);

    RuleItem* oldRule = FindRuleById(newRule->id);
    RuleItem* copied = AllocateRuleItem();
    if (!copied)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = CopyRuleItem(copied, newRule);
    if (!NT_SUCCESS(status)) {
        FreeRuleItem(copied);
        return status;
    }

    if (!oldRule) {
        InsertTailList(&m_rule_list, &copied->ListEntry);
        m_rule_count++;
        return STATUS_SUCCESS;
    }

    PLIST_ENTRY prev = oldRule->ListEntry.Blink;
    RemoveEntryList(&oldRule->ListEntry);
    InsertHeadList(prev, &copied->ListEntry);
    FreeRuleItem(oldRule);
    return STATUS_SUCCESS;
}

NTSTATUS RuleManager::DeleteRule(INT32 id)
{
    ExAcquirePushLockExclusiveEx(&m_lock, 0);

    RuleItem* rule = FindRuleById(id);
    if (!rule) {
        ExReleasePushLockExclusiveEx(&m_lock, 0);
        return STATUS_NOT_FOUND;
    }

    RemoveEntryList(&rule->ListEntry);
    if (m_rule_count)
        m_rule_count--;
    ExReleasePushLockExclusiveEx(&m_lock, 0);

    FreeRuleItem(rule);
    return STATUS_SUCCESS;
}

NTSTATUS RuleManager::BatchUpdateRules(const RuleItem* rules, UINT32 count)
{
    if (!rules && count)
        return STATUS_INVALID_PARAMETER;

    ExAcquirePushLockExclusiveEx(&m_lock, 0);

    NTSTATUS status = STATUS_SUCCESS;
    for (UINT32 i = 0; i < count; i++) {
        NTSTATUS s = UpdateRuleNoLock(rules[i].id, &rules[i]);
        if (!NT_SUCCESS(s) && NT_SUCCESS(status))
            status = s;
    }

    ExReleasePushLockExclusiveEx(&m_lock, 0);
    return status;
}

void RuleManager::ClearAll()
{
    ExAcquirePushLockExclusiveEx(&m_lock, 0);
    ClearAllNoLock();
    ExReleasePushLockExclusiveEx(&m_lock, 0);
}

void RuleManager::ClearAllNoLock()
{
    while (!IsListEmpty(&m_rule_list)) {
        PLIST_ENTRY e = RemoveHeadList(&m_rule_list);
        RuleItem* rule = CONTAINING_RECORD(e, RuleItem, ListEntry);
        FreeRuleItem(rule);
    }
    m_rule_count = 0;
}

NTSTATUS RuleManager::BuildRuleItemFromUserRule(const USER_RULE* userRule, RuleItem* outRule) {
    if (!userRule || !outRule) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;

    outRule->id = userRule->Id;
    outRule->power = userRule->Power;
    outRule->treatment = (Treatment)userRule->Treatment;
    outRule->process_count = userRule->ProcessCount;
    outRule->file_count = userRule->FileCount;
    outRule->registry_count = userRule->RegistryCount;

    outRule->name = AllocateString(userRule->Name);
    outRule->procname = AllocateString(userRule->ProcName);

    if (!outRule->name || !outRule->procname) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    const USER_POLICY* up = userRule->Policies;

    if (userRule->ProcessCount > 0) {
        outRule->process_policies = AllocatePolicyArray(userRule->ProcessCount);
        if (!outRule->process_policies) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        for (UINT32 i = 0; i < userRule->ProcessCount; i++, up++) {
            Policy* p = &outRule->process_policies[i];
            p->action_type.all = up->ActionTypeAll;
            p->res_path = AllocateString(up->ResPath);
            p->res_cmdline = AllocateString(up->ResCmdline);
            if (!p->res_path || !p->res_cmdline) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Cleanup;
            }
        }
    }

    if (userRule->FileCount > 0) {
        outRule->file_policies = AllocatePolicyArray(userRule->FileCount);
        if (!outRule->file_policies) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        for (UINT32 i = 0; i < userRule->FileCount; i++, up++) {
            Policy* p = &outRule->file_policies[i];
            p->action_type.all = up->ActionTypeAll;
            p->res_path = AllocateString(up->ResPath);
            p->res_cmdline = AllocateString(up->ResCmdline);
            if (!p->res_path || !p->res_cmdline) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Cleanup;
            }
        }
    }

    if (userRule->RegistryCount > 0) {
        outRule->registry_policies = AllocatePolicyArray(userRule->RegistryCount);
        if (!outRule->registry_policies) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        for (UINT32 i = 0; i < userRule->RegistryCount; i++, up++) {
            Policy* p = &outRule->registry_policies[i];
            p->action_type.all = up->ActionTypeAll;
            p->res_path = AllocateString(up->ResPath);
            p->res_cmdline = AllocateString(up->ResCmdline);
            if (!p->res_path || !p->res_cmdline) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Cleanup;
            }
        }
    }

    return STATUS_SUCCESS;

Cleanup:
    if (outRule->process_policies) {
        FreePolicyArray(outRule->process_policies, outRule->process_count);
        outRule->process_policies = nullptr;
    }
    if (outRule->file_policies) {
        FreePolicyArray(outRule->file_policies, outRule->file_count);
        outRule->file_policies = nullptr;
    }
    if (outRule->registry_policies) {
        FreePolicyArray(outRule->registry_policies, outRule->registry_count);
        outRule->registry_policies = nullptr;
    }

    FreeString(outRule->name);
    FreeString(outRule->procname);
    outRule->name = nullptr;
    outRule->procname = nullptr;

    return status;
}

RuleItem* RuleManager::FindRuleById(INT32 id)
{
    PLIST_ENTRY entry = m_rule_list.Flink;
    while (entry != &m_rule_list) {
        RuleItem* rule = CONTAINING_RECORD(entry, RuleItem, ListEntry);
        if (rule->id == id)
            return rule;
        entry = entry->Flink;
    }
    return nullptr;
}

static BOOLEAN WildcardMatchInternal(_In_ PCWSTR pat, _In_ PCWSTR str)
{
    if (!pat || !str)
        return FALSE;

    while (*pat) {
        if (*pat == L'*') {
            pat++;
            if (*pat == L'\0')
                return TRUE;
            while (*str) {
                if (WildcardMatchInternal(pat, str))
                    return TRUE;
                str++;
            }
            return FALSE;
        }

        if (*pat == L'?') {
            if (*str == L'\0')
                return FALSE;
            pat++;
            str++;
            continue;
        }

        if (RtlUpcaseUnicodeChar(*pat) != RtlUpcaseUnicodeChar(*str))
            return FALSE;

        pat++;
        str++;
    }

    return (*str == L'\0');
}

BOOLEAN RuleManager::WildcardMatch(PCUNICODE_STRING pattern, PCUNICODE_STRING str) const
{
    if (!pattern || !pattern->Buffer || pattern->Length == 0)
        return TRUE;
    if (!str || !str->Buffer)
        return FALSE;

    if (pattern->Length == sizeof(WCHAR) && pattern->Buffer[0] == L'*')
        return TRUE;

    BOOLEAN match = WildcardMatchInternal(pattern->Buffer, str->Buffer);
    if (match)
        return TRUE;

    for (PCWSTR p = str->Buffer; *p; ++p) {
        if (*p == L'*' || *p == L'?') {
            return WildcardMatchInternal(str->Buffer, pattern->Buffer);
        }
    }

    return FALSE;
}

PWCHAR RuleManager::AllocateString(PCWSTR src)
{
    if (!src)
        return nullptr;

    size_t cch = 0;
    if (!NT_SUCCESS(RtlStringCchLengthW(src, 0x7fff, &cch)))
        return nullptr;

    SIZE_T bytes = (cch + 1) * sizeof(WCHAR);
    PWCHAR dst = (PWCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, bytes, TAG_STRING);
    if (!dst)
        return nullptr;

    RtlZeroMemory(dst, bytes);
    if (!NT_SUCCESS(RtlStringCchCopyW(dst, cch + 1, src))) {
        ExFreePoolWithTag(dst, TAG_STRING);
        return nullptr;
    }

    return dst;
}

void RuleManager::FreeString(PWCHAR str)
{
    if (str)
        ExFreePoolWithTag(str, TAG_STRING);
}

Policy* RuleManager::AllocatePolicyArray(UINT32 count)
{
    if (count == 0)
        return nullptr;

    SIZE_T bytes = (SIZE_T)count * sizeof(Policy);
    Policy* p = (Policy*)ExAllocatePoolWithTag(NonPagedPoolNx, bytes, TAG_POLICY);
    if (!p)
        return nullptr;
    RtlZeroMemory(p, bytes);
    return p;
}

void RuleManager::FreePolicyArray(Policy* policies, UINT32 count)
{
    if (!policies)
        return;

    for (UINT32 i = 0; i < count; i++) {
        FreeString(policies[i].res_path);
        FreeString(policies[i].res_cmdline);
        policies[i].res_path = nullptr;
        policies[i].res_cmdline = nullptr;
    }

    ExFreePoolWithTag(policies, TAG_POLICY);
}

RuleItem* RuleManager::AllocateRuleItem()
{
    RuleItem* rule = (RuleItem*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(RuleItem), TAG_RULE);
    if (!rule)
        return nullptr;
    RtlZeroMemory(rule, sizeof(RuleItem));
    InitializeListHead(&rule->ListEntry);
    return rule;
}

void RuleManager::FreeRuleItem(RuleItem* rule)
{
    if (!rule)
        return;

    FreePolicyArray(rule->process_policies, rule->process_count);
    FreePolicyArray(rule->file_policies, rule->file_count);
    FreePolicyArray(rule->registry_policies, rule->registry_count);

    rule->process_policies = nullptr;
    rule->file_policies = nullptr;
    rule->registry_policies = nullptr;
    rule->process_count = 0;
    rule->file_count = 0;
    rule->registry_count = 0;

    FreeString(rule->name);
    FreeString(rule->procname);
    rule->name = nullptr;
    rule->procname = nullptr;

    ExFreePoolWithTag(rule, TAG_RULE);
}

NTSTATUS RuleManager::CopyPolicy(Policy* dst, const Policy* src)
{
    if (!dst || !src)
        return STATUS_INVALID_PARAMETER;

    dst->action_type = src->action_type;
    dst->res_path = AllocateString(src->res_path ? src->res_path : L"");
    dst->res_cmdline = AllocateString(src->res_cmdline ? src->res_cmdline : L"");

    if (!dst->res_path || !dst->res_cmdline)
        return STATUS_INSUFFICIENT_RESOURCES;

    return STATUS_SUCCESS;
}

NTSTATUS RuleManager::CopyRuleItem(RuleItem* dst, const RuleItem* src)
{
    if (!dst || !src)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(dst, sizeof(*dst));
    InitializeListHead(&dst->ListEntry);

    dst->id = src->id;
    dst->power = src->power;
    dst->treatment = src->treatment;
    dst->process_count = src->process_count;
    dst->file_count = src->file_count;
    dst->registry_count = src->registry_count;

    dst->name = AllocateString(src->name ? src->name : L"");
    dst->procname = AllocateString(src->procname ? src->procname : L"");
    if (!dst->name || !dst->procname)
        return STATUS_INSUFFICIENT_RESOURCES;

    if (src->process_count) {
        dst->process_policies = AllocatePolicyArray(src->process_count);
        if (!dst->process_policies)
            return STATUS_INSUFFICIENT_RESOURCES;
        for (UINT32 i = 0; i < src->process_count; i++) {
            NTSTATUS s = CopyPolicy(&dst->process_policies[i], &src->process_policies[i]);
            if (!NT_SUCCESS(s))
                return s;
        }
    }

    if (src->file_count) {
        dst->file_policies = AllocatePolicyArray(src->file_count);
        if (!dst->file_policies)
            return STATUS_INSUFFICIENT_RESOURCES;
        for (UINT32 i = 0; i < src->file_count; i++) {
            NTSTATUS s = CopyPolicy(&dst->file_policies[i], &src->file_policies[i]);
            if (!NT_SUCCESS(s))
                return s;
        }
    }

    if (src->registry_count) {
        dst->registry_policies = AllocatePolicyArray(src->registry_count);
        if (!dst->registry_policies)
            return STATUS_INSUFFICIENT_RESOURCES;
        for (UINT32 i = 0; i < src->registry_count; i++) {
            NTSTATUS s = CopyPolicy(&dst->registry_policies[i], &src->registry_policies[i]);
            if (!NT_SUCCESS(s))
                return s;
        }
    }

    return STATUS_SUCCESS;
}