#pragma once
#include <ntifs.h>
#include <ntddk.h>

#define TAG_RULE 'elur'  // 'rule'
#define TAG_POLICY 'loop'  // 'pool'
#define TAG_STRING 'rts1'  // 'str1'

// IOCTL 代码定义
#define IOCTL_TOGGLE_PROTECTION     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_RULE              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DELETE_RULE           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_RULES           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BATCH_ADD_RULES       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_NEXT_ASK          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RESPOND_ASK           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REGISTER_CLIENT       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[1zGuard]: " format "\n", ##__VA_ARGS__)

class RuleManager;
typedef struct _RuleItem RuleItem;
typedef struct _BatchRuleRequest BatchRuleRequest;

typedef struct _USER_ASK_REQUEST {
    UINT32 RequestId;
    WCHAR ProcessName[260];
    WCHAR ProcessPath[520];
    WCHAR ResourcePath[520];
    INT32 RuleId;
    WCHAR RuleName[64];
    UINT32 Type;
    UINT32 ActionAll;
    UINT32 TimeoutSeconds;
} USER_ASK_REQUEST;

typedef struct _USER_ASK_RESPONSE {
    UINT32 RequestId;
    UINT32 Decision;
} USER_ASK_RESPONSE;

typedef struct _ASK_QUEUE_NODE {
    LIST_ENTRY ListEntry;
    USER_ASK_REQUEST Request;
} ASK_QUEUE_NODE, *PASK_QUEUE_NODE;

typedef struct _PENDING_ASK {
    LIST_ENTRY ListEntry;
    UINT32 RequestId;
    KEVENT ResponseEvent;
    volatile LONG HasResponse;
    UINT32 Decision;
} PENDING_ASK, *PPENDING_ASK;

typedef NTSTATUS(*PFN_FsRtlCancellableWaitForSingleObject)(PVOID Object, PLARGE_INTEGER Timeout, PVOID Context);

// CSQ IRP 上下文结构
typedef struct _CSQ_IRP_CONTEXT {
    IO_CSQ_IRP_CONTEXT CsqContext;
} CSQ_IRP_CONTEXT, *PCSQ_IRP_CONTEXT;

// 驱动全局变量
typedef struct _GLOBAL_STATE {
    // 总开关
    volatile LONG ProtectionEnabled;

    // 规则管理器
    RuleManager* pRuleManager;

    // CSQ 队列
    IO_CSQ CsqQueue;
    LIST_ENTRY PendingList;
    KSPIN_LOCK QueueLock;
    volatile LONG NextRequestId;

    // Ask 请求队列
    LIST_ENTRY AskQueue;
    KSPIN_LOCK AskQueueLock;

    // Pending Ask 列表
    LIST_ENTRY PendingAskList;
    FAST_MUTEX PendingAskLock;

    // 工作线程
    HANDLE WorkerThreadHandle;
    PKTHREAD WorkerThread;
    KEVENT WorkerShutdown;
    KEVENT QueueNotEmpty;

    PFN_FsRtlCancellableWaitForSingleObject FsRtlCancellableWaitForSingleObject;

    // 共享内存
    PVOID SharedMemoryBase;
    PMDL SharedMemoryMdl;
    SIZE_T SharedMemorySize;
    HANDLE SharedMemorySectionHandle;
    PVOID SharedMemorySectionObject;

    // 命名事件（通知托盘）
    PKEVENT NewRequestEvent;
    HANDLE NewRequestEventHandle;

    // 回调注册句柄
    PVOID MiniFilterHandle;
    volatile LONG MiniFilterPendingOps;
    KEVENT MiniFilterNoPendingOps;
    volatile LONG MiniFilterShutdown;
    LARGE_INTEGER ProcessCallbackCookie;
    LARGE_INTEGER RegistryCallbackCookie;
    
    // 设备和符号链接
    PDEVICE_OBJECT pDeviceObject;
    UNICODE_STRING SymbolicLinkName;

    // 客户端进程路径白名单
    WCHAR ClientProcessPath[520];
    KSPIN_LOCK ClientPathLock;

    // 客户端主进程ID（用于检测进程退出）
    HANDLE MainProcessId;
    KSPIN_LOCK MainProcessIdLock;

    BOOLEAN Initialized;
} GLOBAL_STATE;

extern GLOBAL_STATE g_State;

BOOLEAN GetCurrentProcessName(_Out_ PUNICODE_STRING ProcessName);
BOOLEAN IsCurrentProcessClient();