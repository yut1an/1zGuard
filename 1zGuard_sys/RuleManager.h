#pragma once
#include <ntddk.h>


enum ProtectType {
    Process = 0,
    File = 1,
    Registry = 2
};

typedef union _ActionType {
    UINT32 all;
    struct {
        UINT32 Delete : 1;
        UINT32 Modify : 1;
        UINT32 Read : 1;
        UINT32 Create : 1;
        UINT32 Execute : 1;
        UINT32 Reserved : 27;
    }fields;
}ActionType;

enum Treatment {
    Allow = 0,
    Ask = 1,
    Block = 2
};

// 单条策略
typedef struct _Policy {
    ActionType action_type;
    PWCHAR res_path;      // 支持通配符
    PWCHAR res_cmdline;   // 仅进程有效
}Policy;

// 一条完整规则
typedef struct _RuleItem {
    LIST_ENTRY ListEntry;       // 链表节点
    INT32 id;
    PWCHAR name;          // 规则名称
    PWCHAR procname;      // 发起进程，支持 *
    BOOLEAN power;        // 开关
    Treatment treatment;

    Policy* process_policies;     // montype == 0
    Policy* file_policies;        // montype == 1
    Policy* registry_policies;    // montype == 2

    UINT32 process_count;
    UINT32 file_count;
    UINT32 registry_count;
}RuleItem;

typedef struct _BatchRuleRequest {
    UINT32 RuleCount;
    RuleItem Rules[1];
} BatchRuleRequest;

typedef enum _USER_PROTECT_TYPE {
    UserProtectType_Process = 0,  // 进程策略
    UserProtectType_File = 1,  // 文件策略
    UserProtectType_Registry = 2   // 注册表策略
} USER_PROTECT_TYPE;

// 与 ActionType.all 对应的位标志，直接用 UINT32
typedef struct _USER_POLICY {
    UINT32 ActionTypeAll;       // 对应 ActionType.all
    USER_PROTECT_TYPE Type;     // 0=Process,1=File,2=Registry

    // 路径 / 键名 / 镜像路径，UTF-16，0 结尾
    WCHAR  ResPath[260];

    // 仅 Type == Process 时使用（命令行），其他情况可为空串 ""
    WCHAR  ResCmdline[260];
} USER_POLICY;

// 单条规则（变长数组）
typedef struct _USER_RULE {
    INT32  Id;
    WCHAR  Name[64];            // 规则名
    WCHAR  ProcName[260];       // 发起进程，可为 L"*"
    BOOLEAN Power;              // 开关
    UINT32 Treatment;           // 0 Allow, 1 Ask, 2 Block

    UINT32 ProcessCount;
    UINT32 FileCount;
    UINT32 RegistryCount;

    // 紧跟着的是 ProcessCount + FileCount + RegistryCount 个 USER_POLICY，
    // 顺序约定：先所有 Process，再所有 File，再所有 Registry
    USER_POLICY Policies[1];    // 可变长数组
} USER_RULE;

// 批量规则请求（变长）
typedef struct _USER_BATCH_RULE_REQUEST {
    UINT32 RuleCount;
    // 紧跟着是 RuleCount 个 USER_RULE（每个又是变长）
    UCHAR   Data[1];
} USER_BATCH_RULE_REQUEST;

class RuleManager {
public:

    // 初始化和清理
    NTSTATUS Initialize();
    void Uninitialize();

    // 规则管理
    NTSTATUS UpdateRule(INT32 id, const RuleItem* newRule);
    NTSTATUS UpdateRuleNoLock(INT32 id, const RuleItem* newRule);
    NTSTATUS DeleteRule(INT32 id);
    NTSTATUS BatchUpdateRules(const RuleItem* rules, UINT32 count);
    void ClearAll();
    void ClearAllNoLock();

    NTSTATUS BuildRuleItemFromUserRule(const USER_RULE* userRule, RuleItem* outRule);
    RuleItem* AllocateRuleItem();
    void FreeRuleItem(RuleItem* rule);

    // 匹配函数不变
    UINT8 MatchRegistry(PCUNICODE_STRING processName, ActionType action, PCUNICODE_STRING keyPath) const;
    UINT8 MatchRegistryEx(
        _In_opt_ PCUNICODE_STRING processName,
        _In_ ActionType action,
        _In_ PCUNICODE_STRING keyPath,
        _Out_opt_ INT32* ruleId,
        _Out_writes_(ruleNameCch) PWCHAR ruleName,
        _In_ ULONG ruleNameCch) const;

    UINT8 MatchFile(PCUNICODE_STRING processName, ActionType action, PCUNICODE_STRING filePath) const;
    UINT8 MatchFileEx(
        _In_opt_ PCUNICODE_STRING processName,
        _In_ ActionType action,
        _In_ PCUNICODE_STRING filePath,
        _Out_opt_ INT32* ruleId,
        _Out_writes_(ruleNameCch) PWCHAR ruleName,
        _In_ ULONG ruleNameCch) const;
    UINT8 MatchProcess(PCUNICODE_STRING processName, ActionType action, PCUNICODE_STRING imagePath, PCUNICODE_STRING cmdline = nullptr) const;

    UINT8 MatchProcessEx(
        _In_opt_ PCUNICODE_STRING parentProcessName,
        _In_ ActionType action,
        _In_ PCUNICODE_STRING childImagePath,
        _In_opt_ PCUNICODE_STRING childArgs,
        _Out_opt_ INT32* ruleId,
        _Out_writes_(ruleNameCch) PWCHAR ruleName,
        _In_ ULONG ruleNameCch) const;

    // 获取规则数量
    UINT32 GetRuleCount() const { return m_rule_count; }

    //// 禁止拷贝
    //RuleManager(const RuleManager&) = delete;
    //RuleManager& operator=(const RuleManager&) = delete;
    RuleManager(){}
private:

    // 查找规则
    RuleItem* FindRuleById(INT32 id);

    // 通配符匹配
    BOOLEAN WildcardMatch(PCUNICODE_STRING pattern, PCUNICODE_STRING str) const;

    // 内存管理
    //RuleItem* AllocateRuleItem();
    //void FreeRuleItem(RuleItem* rule);
    Policy* AllocatePolicyArray(UINT32 count);
    void FreePolicyArray(Policy* policies, UINT32 count);
    PWCHAR AllocateString(PCWSTR src);
    void FreeString(PWCHAR str);

    // 深拷贝
    NTSTATUS CopyRuleItem(RuleItem* dst, const RuleItem* src);
    NTSTATUS CopyPolicy(Policy* dst, const Policy* src);

    // 通用匹配逻辑
    UINT8 MatchInternal(PCUNICODE_STRING processName, ActionType action, PCUNICODE_STRING resourcePath, ProtectType type) const;

private:
    LIST_ENTRY m_rule_list;                     // 规则链表头
    UINT32 m_rule_count;                        // 规则数量
    mutable EX_PUSH_LOCK m_lock;
    PNPAGED_LOOKASIDE_LIST m_rule_lookaside;    // RuleItem 旁视链表
    PNPAGED_LOOKASIDE_LIST m_policy_lookaside;  // Policy 旁视链表
    BOOLEAN m_initialized;                      // 初始化标志
};

