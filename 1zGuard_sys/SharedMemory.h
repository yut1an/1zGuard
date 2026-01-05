#pragma once
#include "Common.h"
#include "RuleManager.h"

#define MAX_ASK 0xff



// 询问请求（驱动 → 应用层）
typedef struct _SHARED_ASK_REQUEST {
    volatile BOOLEAN Active;           // 是否有活跃请求
    UINT32 RequestId;                  // 请求ID
    WCHAR ProcessName[260];            // 发起进程
    WCHAR ProcessPath[520];            // 进程完整路径
    WCHAR ResourcePath[520];           // 资源路径（文件/注册表/进程）
    INT32 RuleId;                      // 命中规则ID
    WCHAR RuleName[64];                // 命中规则名称
    ProtectType Type;                  // 保护类型
    ActionType Action;                 // 操作类型
    UINT32 TimeoutSeconds;             // 剩余秒数（倒计时）

    // 用户决策结果（托盘写入）
    volatile Treatment Decision;       // 用户决策
    volatile BOOLEAN Ready;            // 是否已决策

    LARGE_INTEGER Timestamp;           // 时间戳
} SHARED_ASK_REQUEST;

// 完整的共享内存布局
typedef struct _SHARED_MEMORY {
    // ========== 当前活跃请求（串行，只有一个）==========
    SHARED_ASK_REQUEST CurrentRequest;

    // ========== 统计信息 ==========
    volatile LONG TotalAsked;        // 总询问次数
    volatile LONG PendingCount;      // 队列中等待的数量
    volatile LONG AllowedCount;      // 用户允许次数
    volatile LONG BlockedCount;      // 用户阻止次数
    volatile LONG TimeoutCount;      // 超时次数
} SHARED_MEMORY;

NTSTATUS InitializeSharedMemory(_In_ PDRIVER_OBJECT DriverObject);
VOID UninitializeSharedMemory();
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
    );