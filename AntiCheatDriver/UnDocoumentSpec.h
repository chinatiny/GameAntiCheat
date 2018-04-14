#pragma  once
#include "AntiCheatDriver.h"

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;    //双向链表
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct _no_name_struct{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct tagSYSTEM_MODULE_INFORMATION {
	ULONG Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemNotImplemented1,
	SystemProcessesAndThreadsInformation,
	SystemCallCounts,
	SystemConfigurationInformation,
	SystemProcessorTimes,
	SystemGlobalFlag,
	SystemNotImplemented2,
	SystemModuleInformation,
	SystemLockInformation,
	SystemNotImplemented3,
	SystemNotImplemented4,
	SystemNotImplemented5,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPagefileInformation,
	SystemInstructionEmulationCounts,
	SystemInvalidInfoClass1,
	SystemCacheInformation,
	SystemPoolTagInformation,
	SystemProcessorStatistics,
	SystemDpcInformation,
	SystemNotImplemented6,
	SystemLoadImage,
	SystemUnloadImage,
	SystemTimeAdjustment,
	SystemNotImplemented7,
	SystemNotImplemented8,
	SystemNotImplemented9,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemLoadAndCallImage,
	SystemPrioritySeparation,
	SystemNotImplemented10,
	SystemNotImplemented11,
	SystemInvalidInfoClass2,
	SystemInvalidInfoClass3,
	SystemTimeZoneInformation,
	SystemLookasideInformation,
	SystemSetTimeSlipEvent,
	SystemCreateSession,
	SystemDeleteSession,
	SystemInvalidInfoClass4,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemAddVerifier,
	SystemSessionProcessesInformation
} SYSTEM_INFORMATION_CLASS;


NTSTATUS ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength);

PVOID NTAPI RtlImageDirectoryEntryToData(IN PVOID  BaseAddress,
	IN BOOLEAN        ImageLoaded,
	IN ULONG  Directory,
	OUT PULONG        Size);

PVOID PsGetProcessDebugPort(IN PEPROCESS Process);
NTKERNELAPI PVOID PsGetProcessPeb(IN PEPROCESS Process);
NTKERNELAPI HANDLE PsGetProcessId(IN PEPROCESS Process);
NTKERNELAPI UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);




#define	THREAD_TERMINATE 									 (0x0001)
#define	THREAD_SUSPEND_RESUME  						 (0x0002)

#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  


//apc相关
typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef VOID(*PKNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
	);

typedef VOID(*PKKERNEL_ROUTINE) (
	IN struct _KAPC *Apc,
	IN OUT PKNORMAL_ROUTINE *NormalRoutine,
	IN OUT PVOID *NormalContext,
	IN OUT PVOID *SystemArgument1,
	IN OUT PVOID *SystemArgument2
	);

typedef VOID(*PKRUNDOWN_ROUTINE) (
	IN struct _KAPC *Apc
	);

VOID NTAPI KeInitializeApc(__in PKAPC 	Apc,
	__in PKTHREAD 	Thread,
	__in KAPC_ENVIRONMENT 	TargetEnvironment,
	__in PKKERNEL_ROUTINE 	KernelRoutine,
	__in_opt PKRUNDOWN_ROUTINE 	RundownRoutine,
	__in PKNORMAL_ROUTINE 	NormalRoutine,
	__in KPROCESSOR_MODE 	Mode,
	__in PVOID 	Context
	);


BOOLEAN  NTAPI KeInsertQueueApc(IN PKAPC Apc,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2,
	IN KPRIORITY PriorityBoost);

#define OFFSET(type, f) ((SIZE_T) \
	((char *)&((type *)0)->f - (char *)(type *)0))
