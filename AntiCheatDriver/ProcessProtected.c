#include "ProcessProtected.h"
#include "UnDocoumentSpec.h"

//通过注册回调进行保护
NeedProtectedObj g_needProtectObj = { 0, 0, 0 };
PVOID g_pRegiHandle = NULL;
NTSTATUS g_RegisterCallbacks = STATUS_UNSUCCESSFUL;

//////通过inlinehook进行保护
typedef VOID (*fpTypeKeStackAttachProcess)(
	_Inout_ PRKPROCESS PROCESS,
	_Out_ PRKAPC_STATE ApcState
	);
typedef NTSTATUS (*fpTypeNtOpenThread)(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
	);
typedef NTSTATUS (*fpTypeNtDuplicateObject)(
	IN HANDLE SourceProcessHandle,
	IN HANDLE SourceHandle,
	IN HANDLE TargetProcessHandle OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options
	);
typedef NTSTATUS (*fpTypeNtOpenProcess)(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	);
typedef NTSTATUS (*fpTypeNtCreateDebugObject)(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
	);
typedef BOOLEAN (*fpTypeKeInsertQueueApc)(IN PKAPC Apc,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2,
	IN KPRIORITY PriorityBoost);  //防止插入apc

typedef NTSTATUS(*fpTypeKeUserModeCallback)(
	IN ULONG ApiNumber,
	IN PVOID InputBuffer,
	IN ULONG InputLength,
	OUT PVOID *OutputBuffer,
	IN PULONG OutputLength
	);//对部分的内核回调做限制

typedef BOOLEAN (*fpTypeMmIsAddressValid)(
	_In_  PVOID VirtualAddress
	);//隐藏hook


typedef NTSTATUS (*fpTypeNtUserBuildHwndList)(IN HDESK hdesk,
	IN HWND hwndNext, 
	IN ULONG fEnumChildren, 
	IN DWORD idThread, 
	IN UINT cHwndMax, 
	OUT HWND *phwndFirst, 
	OUT ULONG* pcHwndNeeded);  //遍历窗体

typedef ULONG(*fpTypeNtUserGetForegroundWindow)(VOID); //GetForegroundWindow 得到当前顶层窗口

typedef UINT_PTR  (*fpTypeNtUserQueryWindow)(IN ULONG WindowHandle, IN ULONG TypeInformation); //GetWindowThreadProcessId 获取句柄对应的进程PID

typedef NTSTATUS(*fpTypeNtUserFindWindowEx)(
	IN HWND hwndParent,
	IN HWND hwndChild,
	IN PUNICODE_STRING pstrClassName OPTIONAL,
	IN PUNICODE_STRING pstrWindowName OPTIONAL,
	IN DWORD dwType); //FindWindow 查找窗口获取句柄


typedef NTSTATUS (*fpTypeNtUserPostMessage)(
	IN HWND hWnd,
	IN ULONG pMsg,
	IN ULONG wParam,
	IN ULONG lParam
	); //PostMessage


typedef BOOL(*fpTypeNtUserPostThreadMessage)(
	IN DWORD idThread,
	IN UINT Msg,
	IN ULONG wParam,
	IN ULONG lParam
	); //SendMessage

typedef HHOOK(*fpTypeNtUserSetWindowsHookEx)(
	HINSTANCE Mod,
	PUNICODE_STRING UnsafeModuleName,
	DWORD ThreadId,
	int HookId,
	PVOID HookProc,
	BOOL Ansi); //设置钩子

typedef UINT (*fpTypeNtUserSendInput)(
	IN UINT    cInputs,
	IN CONST INPUT *pInputs,
	IN int     cbSize
	); //SendInput


//关于调试、进程、线程、apc、内核回调的hook
InlineHookFunctionSt g_inlineKeStackAttachProcess = { 0 };
InlineHookFunctionSt g_inlineNtOpenThread = { 0 };
InlineHookFunctionSt g_inlineNtDuplicateObject = { 0 };
InlineHookFunctionSt g_inlineNtOpenProcess = { 0 };
InlineHookFunctionSt g_inlineNtCreateDebugObject = { 0 };
InlineHookFunctionSt g_inlineKeInsertQueueApc = { 0 };
InlineHookFunctionSt g_inlineKeUserModeCallBack = { 0 };
InlineHookFunctionSt g_inlineMmIsAddressValid = { 0 };
//关于界面相关的hook
InlineHookFunctionSt g_inlineNtUserBuildHwndList = { 0 };
InlineHookFunctionSt g_inlineNtUserGetForegroundWindow = { 0 };
InlineHookFunctionSt g_inlineNtUserQueryWindow = { 0 };
InlineHookFunctionSt g_inlineNtUserFindWindowEx = { 0 };
InlineHookFunctionSt g_inlineNtUserPostMessage = { 0 };
InlineHookFunctionSt g_inlineNtUserPostThreadMessage = { 0 };
InlineHookFunctionSt g_inlineNtUserSetWindowsHookEx = { 0 };
InlineHookFunctionSt g_inlineNtUserSendInput = { 0 };


void InstallInlineHookProtected();
void UninstallInlineHookProtected();
VOID FakeKeStackAttachProcess(
	_Inout_ PRKPROCESS PROCESS, 
	_Out_ PRKAPC_STATE ApcState); //山寨版本的进程挂靠 
NTSTATUS FakeNtOpenThread(
	OUT PHANDLE ThreadHandle, 
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes, 
	IN PCLIENT_ID ClientId);//山寨版本的打开线程
NTSTATUS FakeNtDuplicateObject(
	IN HANDLE SourceProcessHandle,
	IN HANDLE SourceHandle,
	IN HANDLE TargetProcessHandle OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options
	);//山寨版本的句柄复制

NTSTATUS FakeNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	);//山寨版本的打开进程

NTSTATUS FakeNtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
	);//创建调试对象

BOOLEAN  FakeKeInsertQueueApc(IN PKAPC Apc,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2,
	IN KPRIORITY PriorityBoost); //过滤插入apc，防止别人自己实现挂起、关闭进程、防止内核apc注入

NTSTATUS FakeKeUserModeCallback(
	IN ULONG ApiNumber,
	IN PVOID InputBuffer,
	IN ULONG InputLength,
	OUT PVOID *OutputBuffer,
	IN PULONG OutputLength
	);//对部分的内核回调做限制特别是0x41

BOOLEAN FakeMmIsAddressValid(
	_In_  PVOID VirtualAddress
	);//隐藏HOOk

NTSTATUS FakeNtUserBuildHwndList(IN HDESK hdesk,
	IN HWND hwndNext,
	IN ULONG fEnumChildren,
	IN DWORD idThread,
	IN UINT cHwndMax,
	OUT HWND *phwndFirst,
	OUT ULONG* pcHwndNeeded);  //遍历窗体

ULONG FakeNtUserGetForegroundWindow(VOID);  //获取底层窗口

UINT_PTR FakeNtUserQueryWindow(
	IN ULONG WindowHandle, 
	IN ULONG TypeInformation); //GetWindowThreadProcessId 获取句柄对应的进程PID

NTSTATUS FakeNtUserFindWindowEx(
	IN HWND hwndParent,
	IN HWND hwndChild,
	IN PUNICODE_STRING pstrClassName OPTIONAL,
	IN PUNICODE_STRING pstrWindowName OPTIONAL,
	IN DWORD dwType); //FindWindow 查找窗口获取句柄

NTSTATUS FakeNtUserPostMessage(
	IN HWND hWnd,
	IN ULONG pMsg,
	IN ULONG wParam,
	IN ULONG lParam
	); //PostMessage

BOOL FakeNtUserPostThreadMessage(
	IN DWORD idThread,
	IN UINT Msg,
	IN ULONG wParam,
	IN ULONG lParam
	); //SendMessage

HHOOK FakeNtUserSetWindowsHookEx(
	HINSTANCE Mod,
	PUNICODE_STRING UnsafeModuleName,
	DWORD ThreadId,
	int HookId,
	PVOID HookProc,
	BOOL Ansi); //设置钩子

UINT FakeNtUserSendInput(
	IN UINT    cInputs,
	IN CONST INPUT *pInputs,
	IN int     cbSize
	); //SendInput


//降权处理
OB_PREOP_CALLBACK_STATUS MyObjectPreCallback(
	__in PVOID  RegistrationContext,
	__in POB_PRE_OPERATION_INFORMATION  OperationInformation)
{
	if (g_needProtectObj.uGameProcessID == (ULONG)PsGetProcessId((PEPROCESS)OperationInformation->Object) &&
		g_needProtectObj.uGameProcessID != (ULONG)PsGetCurrentProcessId()
		)
	{
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_DUP_HANDLE) == PROCESS_DUP_HANDLE)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}

//注册保护
void RegisterProtected()
{
	OB_OPERATION_REGISTRATION oor;
	OB_CALLBACK_REGISTRATION ob;
	oor.ObjectType = PsProcessType;
	oor.Operations = OB_OPERATION_HANDLE_CREATE;
	oor.PreOperation = MyObjectPreCallback;
	oor.PostOperation = NULL;

	ob.Version = OB_FLT_REGISTRATION_VERSION;
	ob.OperationRegistrationCount = 1;
	ob.OperationRegistration = &oor;
	RtlInitUnicodeString(&ob.Altitude, L"321000");
	ob.RegistrationContext = NULL;
	g_RegisterCallbacks = ObRegisterCallbacks(&ob, &g_pRegiHandle);
}

//反注册保护
void UnRegisterProtected()
{
	if (STATUS_SUCCESS == g_RegisterCallbacks)
	{
		ObUnRegisterCallbacks(g_pRegiHandle);
		memset(&g_needProtectObj, 0, sizeof(g_needProtectObj));
		g_pRegiHandle = NULL;
		g_RegisterCallbacks = STATUS_UNSUCCESSFUL;

	}
	UninstallInlineHookProtected();
	
}


//设置需要保护的对象
void SetProcessProtected(ULONG uRcvMsgThreadID, ULONG uCheckHeartThreadID, ULONG uProcessID)
{
	g_needProtectObj.uRcvMsgThreadID = uRcvMsgThreadID;
	g_needProtectObj.uCheckHeartThreadID = uCheckHeartThreadID;
	g_needProtectObj.uGameProcessID = uProcessID;
	//使用回调保护游戏
	RegisterProtected();
	//启动hook保护游戏
	InstallInlineHookProtected();

}


void InstallInlineHookProtected()
{
	BOOL bInstallRet = FALSE;

	//防止进程挂靠
	UNICODE_STRING strKeStackAttachProcess;
	RtlInitUnicodeString(&strKeStackAttachProcess, L"KeStackAttachProcess");
	PVOID pfnKeStackAttachProcessAddr = MmGetSystemRoutineAddress(&strKeStackAttachProcess);
	InitInlineHookFunction(&g_inlineKeStackAttachProcess, pfnKeStackAttachProcessAddr, FakeKeStackAttachProcess);
	bInstallRet = InstallInlineHookFunction(&g_inlineKeStackAttachProcess);
	KdPrint(("KeStackAttachProcess 安装结果:%d\n", bInstallRet));


	//防止线程被操作，避免别人阻塞和关闭线程
	PVOID pfnNtOpenThread = GetSSDTFuncAddrByName("NtOpenThread");
	InitInlineHookFunction(&g_inlineNtOpenThread, pfnNtOpenThread, FakeNtOpenThread);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtOpenThread);
	KdPrint(("NtOpenThread 安装结果:%d\n", bInstallRet));

	//防止句柄复制
	PVOID pfnNtDuplicateObject = GetSSDTFuncAddrByName("NtDuplicateObject");
	InitInlineHookFunction(&g_inlineNtDuplicateObject, pfnNtDuplicateObject, FakeNtDuplicateObject);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtDuplicateObject);
	KdPrint(("NtDuplicateObject 安装结果:%d\n", bInstallRet));

	//防止以读写权限打开进程
	PVOID pfnNtOpenProcess = GetSSDTFuncAddrByName("NtOpenProcess");
	InitInlineHookFunction(&g_inlineNtOpenProcess, pfnNtOpenProcess, FakeNtOpenProcess);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtOpenProcess);
	KdPrint(("NtOpenProcess 安装结果:%d\n", bInstallRet));

	//防止创建调试对象
	PVOID pfnNtCreateDebugObject = GetSSDTFuncAddrByName("NtCreateDebugObject");
	InitInlineHookFunction(&g_inlineNtCreateDebugObject, pfnNtCreateDebugObject, FakeNtCreateDebugObject);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtCreateDebugObject);
	KdPrint(("NtCreateDebugObject 安装结果:%d\n", bInstallRet));

	//防止插入非法的apc，apc可以实现线程挂起、杀死线程等操作
	UNICODE_STRING strKeInsertQueueApc;
	RtlInitUnicodeString(&strKeInsertQueueApc, L"KeInsertQueueApc");
	PVOID pfnKeInsertQueueApc = MmGetSystemRoutineAddress(&strKeInsertQueueApc);
	InitInlineHookFunction(&g_inlineKeInsertQueueApc, pfnKeInsertQueueApc, FakeKeInsertQueueApc);
	bInstallRet = InstallInlineHookFunction(&g_inlineKeInsertQueueApc);
	KdPrint(("FakeKeInsertQueueApc 安装结果:%d\n", bInstallRet));

	//防止非法的内核回调，比如消息钩子
	UNICODE_STRING strKeUserModeCallback;
	RtlInitUnicodeString(&strKeUserModeCallback, L"KeUserModeCallback");
	PVOID pfnKeUserModeCallback = MmGetSystemRoutineAddress(&strKeUserModeCallback);
	InitInlineHookFunction(&g_inlineKeUserModeCallBack, pfnKeUserModeCallback, FakeKeUserModeCallback);
	bInstallRet = InstallInlineHookFunction(&g_inlineKeUserModeCallBack);
	KdPrint(("KeUserModeCallback 安装结果:%d\n", bInstallRet));


	//hookMmIsAddressValid
	UNICODE_STRING strMmIsAddressValid;
	RtlInitUnicodeString(&strMmIsAddressValid, L"MmIsAddressValid");
	PVOID pfnMmIsAddressValid = MmGetSystemRoutineAddress(&strMmIsAddressValid);
	InitInlineHookFunction(&g_inlineMmIsAddressValid, pfnMmIsAddressValid, FakeMmIsAddressValid);
	bInstallRet = InstallInlineHookFunction(&g_inlineMmIsAddressValid);
	KdPrint(("MmIsAddressValid 安装结果:%d\n", bInstallRet));

	//EnumWindows 枚举所有顶层窗口
	PVOID pfnNtUserBuildHwndList = GetShadowSSDTFuncAddrByName("NtUserBuildHwndList");
	InitInlineHookFunction(&g_inlineNtUserBuildHwndList, pfnNtUserBuildHwndList, FakeNtUserBuildHwndList);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserBuildHwndList);
	KdPrint(("NtUserBuildHwndList 安装结果:%d\n", bInstallRet));

	//GetForegroundWindow 得到当前顶层窗口
	PVOID pfnNtUserGetForegroundWindow = GetShadowSSDTFuncAddrByName("NtUserGetForegroundWindow");
	InitInlineHookFunction(&g_inlineNtUserGetForegroundWindow, pfnNtUserGetForegroundWindow, FakeNtUserGetForegroundWindow);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserGetForegroundWindow);
	KdPrint(("NtUserGetForegroundWindow 安装结果:%d\n", bInstallRet));


	//GetWindowThreadProcessId 获取句柄对应的进程PID
	PVOID pfnNtUserQueryWindow = GetShadowSSDTFuncAddrByName("NtUserQueryWindow");
	InitInlineHookFunction(&g_inlineNtUserQueryWindow, pfnNtUserQueryWindow, FakeNtUserQueryWindow);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserQueryWindow);
	KdPrint(("NtUserQueryWindow 安装结果:%d\n", bInstallRet));


	//NtUserFindWindowEx
	PVOID pfnNtUserFindWindowEx = GetShadowSSDTFuncAddrByName("NtUserFindWindowEx");
	InitInlineHookFunction(&g_inlineNtUserFindWindowEx, pfnNtUserFindWindowEx, FakeNtUserFindWindowEx);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserFindWindowEx);
	KdPrint(("NtUserFindWindowEx 安装结果:%d\n", bInstallRet));

	//NtUserPostMessage
	PVOID pfnNtUserPostMessage = GetShadowSSDTFuncAddrByName("NtUserPostMessage");
	InitInlineHookFunction(&g_inlineNtUserPostMessage, pfnNtUserPostMessage, FakeNtUserPostMessage);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserPostMessage);
	KdPrint(("NtUserPostMessage 安装结果:%d\n", bInstallRet));

	//NtUserPostThreadMessage
	PVOID pfnNtUserPostThreadMessage = GetShadowSSDTFuncAddrByName("NtUserPostThreadMessage");
	InitInlineHookFunction(&g_inlineNtUserPostThreadMessage, pfnNtUserPostThreadMessage, FakeNtUserPostThreadMessage);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserPostThreadMessage);
	KdPrint(("NtUserPostThreadMessage 安装结果:%d\n", bInstallRet));

	//NtUserPostThreadMessage
	PVOID pfnNtUserSetWindowsHookEx = GetShadowSSDTFuncAddrByName("NtUserSetWindowsHookEx");
	InitInlineHookFunction(&g_inlineNtUserSetWindowsHookEx, pfnNtUserSetWindowsHookEx, FakeNtUserSetWindowsHookEx);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserSetWindowsHookEx);
	KdPrint(("NtUserPostThreadMessage 安装结果:%d\n", bInstallRet));


	//NtUserSendInput
	PVOID pfnNtUserSendInput = GetShadowSSDTFuncAddrByName("NtUserSendInput");
	InitInlineHookFunction(&g_inlineNtUserSendInput, pfnNtUserSendInput, FakeNtUserSendInput);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserSendInput);
	KdPrint(("NtUserSendInput 安装结果:%d\n", bInstallRet));
}



void UninstallInlineHookProtected()
{
	//关于调试、进程、线程、apc、内核回调的hook
	UninstallInlineHookFunction(&g_inlineKeStackAttachProcess);
	UninstallInlineHookFunction(&g_inlineNtOpenThread);
	UninstallInlineHookFunction(&g_inlineNtDuplicateObject);
	UninstallInlineHookFunction(&g_inlineNtOpenProcess);
	UninstallInlineHookFunction(&g_inlineNtCreateDebugObject);
	UninstallInlineHookFunction(&g_inlineKeInsertQueueApc);
	UninstallInlineHookFunction(&g_inlineKeUserModeCallBack);
	UninstallInlineHookFunction(&g_inlineMmIsAddressValid);

	//关于界面相关的hook
	UninstallInlineHookFunction(&g_inlineNtUserBuildHwndList);
	UninstallInlineHookFunction(&g_inlineNtUserGetForegroundWindow);
	UninstallInlineHookFunction(&g_inlineNtUserFindWindowEx);
	UninstallInlineHookFunction(&g_inlineNtUserPostMessage);
	UninstallInlineHookFunction(&g_inlineNtUserPostThreadMessage);
	UninstallInlineHookFunction(&g_inlineNtUserSetWindowsHookEx);
	UninstallInlineHookFunction(&g_inlineNtUserSendInput);
}


//防止进程被挂靠
VOID FakeKeStackAttachProcess(
	_Inout_ PRKPROCESS PROCESS,
	_Out_ PRKAPC_STATE ApcState
	)
{
	HANDLE  targetProcessId = PsGetProcessId(PROCESS);
	fpTypeKeStackAttachProcess pFun = (fpTypeKeStackAttachProcess)g_inlineKeStackAttachProcess.pNewHookAddr;
	HANDLE currentProcessId = PsGetCurrentProcessId();
	PEPROCESS currentProcess = PsGetCurrentProcess();
	PUCHAR szCurrentProcessName = PsGetProcessImageFileName(currentProcess);
	//
	if (g_needProtectObj.uGameProcessID != 0 &&
		targetProcessId == (HANDLE)g_needProtectObj.uGameProcessID &&
		currentProcessId != targetProcessId)
	{

		if (!_strnicmp((char*)szCurrentProcessName, "csrss.exe", 9) ||
			!_strnicmp((char*)szCurrentProcessName, "lsass.exe", 9) ||
			!_strnicmp((char*)szCurrentProcessName, "svchost.exe", 11)||
			!_strnicmp((char*)szCurrentProcessName, "explorer.exe", 12)
			)
		{
			pFun(PROCESS, ApcState);
		}
		else
		{
			KdPrint(("进程id:%d尝试挂靠保护进程已经被拦截\n", PsGetProcessId(PROCESS)));
			pFun(currentProcess, ApcState);
		}
	}
	else
	{
		pFun(PROCESS, ApcState);
	}

}

NTSTATUS FakeNtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId)
{
 	NTSTATUS status;
	PEPROCESS currentProcess = NULL;
	PUCHAR szCurrentProcessName = NULL;
	PETHREAD targetThread = NULL;
	PEPROCESS targetProcess = NULL;
	HANDLE targetProcessId = 0;


	//获取打开进程的信息
	currentProcess = PsGetCurrentProcess();
	szCurrentProcessName = PsGetProcessImageFileName(currentProcess);

	fpTypeNtOpenThread pFun = (fpTypeNtOpenThread)g_inlineNtOpenThread.pNewHookAddr;

	//根据线程id获取线程对应的进程结构体
	status = PsLookupThreadByThreadId(ClientId->UniqueThread, &targetThread);
	if (!NT_SUCCESS(status))
		return status;

	//根据线程id获取对应的进程
	targetProcess = IoThreadToProcess(targetThread);
	targetProcessId = PsGetProcessId(targetProcess);

	//开始做保护了
	if (0 != g_needProtectObj.uGameProcessID)
	{
		if (targetProcessId == (HANDLE)g_needProtectObj.uGameProcessID &&
			targetProcessId != PsGetProcessId(currentProcess))  //如果目标进程是保护进程且当前进程id不是本进程才开始保护逻辑
		{

			if (!_strnicmp((char*)szCurrentProcessName, "csrss.exe", 9) ||
				!_strnicmp((char*)szCurrentProcessName, "lsass.exe", 9) ||
				!_strnicmp((char*)szCurrentProcessName, "svchost.exe", 11)||  //需要处理几个特殊的进程
				!_strnicmp((char*)szCurrentProcessName, "explorer.exe", 12)
				)
			{
				status = pFun(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
			}
			else
			{
				KdPrint(("有进程尝试打开保护进程的线程， 进程名为:%s\n", szCurrentProcessName));
				//降权处理
				DesiredAccess &= ~(THREAD_TERMINATE | THREAD_SUSPEND_RESUME);
				status = pFun(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
			}
		}
		else  //自己操作自己，或者别的进程不管
		{
			status = pFun(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
		}
	}
	else//保护还没有初始化
	{
		status = pFun(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
	}
	ObDereferenceObject(targetThread);
	return status;
}

NTSTATUS FakeNtDuplicateObject(
	IN HANDLE SourceProcessHandle,
	IN HANDLE SourceHandle,
	IN HANDLE TargetProcessHandle OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options
	)
{
	NTSTATUS status;
	PEPROCESS currentProcess = NULL;
	PUCHAR szCurrentProcessName = NULL;
	PETHREAD targetThread = NULL;
	PEPROCESS targetProcess = NULL;
	HANDLE targetProcessId = 0;

	fpTypeNtDuplicateObject pFun = (fpTypeNtDuplicateObject)g_inlineNtDuplicateObject.pNewHookAddr;

	//分为内核句柄和用户句柄分开处理
    //#define KERNEL_HANDLE_MASK ((ULONG_PTR)((LONG)0x80000000))
	//根据wrk的代码，可以看出来如果小于零代表是内核句柄

	if ((int)SourceProcessHandle < 0)  //在pscid/内核句柄表中的直接不处理
	{
		status = pFun(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
	}
	else
	{
		//获取SourceProcessHandle对应的进程
		status = ObReferenceObjectByHandle(SourceProcessHandle, PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, &targetProcess, NULL);
		if (!NT_SUCCESS(status))  //说明目标进程不在我的句柄表中直接不处理
		{
			status = pFun(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
		}
		else if (g_needProtectObj.uGameProcessID !=0)
		{
			targetProcessId = PsGetProcessId(targetProcess);
			currentProcess = PsGetCurrentProcess();

			if ((HANDLE)g_needProtectObj.uGameProcessID == targetProcessId)  //若果保护的进程id就是目标进程
			{
				szCurrentProcessName = PsGetProcessImageFileName(currentProcess);
				KdPrint(("进程:%s尝试对游戏进程句柄复制被阻拦\n", szCurrentProcessName));
				status = STATUS_UNSUCCESSFUL;
			}
			else
			{
				status = pFun(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
			}
		}
		else
		{
			status = pFun(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
		}
	}
	return status;
}


NTSTATUS FakeNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	)
{
	NTSTATUS status;
	PEPROCESS currentProcess = NULL;
	PUCHAR szCurrentProcessName = NULL;
	PETHREAD targetThread = NULL;
	PEPROCESS targetProcess = NULL;
	HANDLE targetProcessId = 0;
	HANDLE currentProcessId = 0;

	fpTypeNtOpenProcess pFun = (fpTypeNtOpenProcess)g_inlineNtOpenProcess.pNewHookAddr;
	status = PsLookupProcessByProcessId(ClientId->UniqueProcess, &targetProcess);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	targetProcessId = PsGetProcessId(targetProcess);
	currentProcess = PsGetCurrentProcess();
	currentProcessId = PsGetProcessId(currentProcess);
	szCurrentProcessName = PsGetProcessImageFileName(currentProcess);

	if (g_needProtectObj.uGameProcessID != 0)
	{
		if (targetProcessId == (HANDLE)g_needProtectObj.uGameProcessID &&
			currentProcessId != targetProcessId
			)
		{


			if (!_strnicmp((char*)szCurrentProcessName, "csrss.exe", 9) ||
				!_strnicmp((char*)szCurrentProcessName, "lsass.exe", 9) ||
				!_strnicmp((char*)szCurrentProcessName, "svchost.exe", 11)||  //需要处理几个特殊的进程
				!_strnicmp((char*)szCurrentProcessName, "explorer.exe", 12)
				)
			{
				status = pFun(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
			}
			else
			{
				KdPrint(("有进程尝试打开保护进程，进程名:%s\n", szCurrentProcessName));
				//降权处理
				DesiredAccess &= ~(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | \
					PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE \
					| PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME);
				status = pFun(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
			}
		}
		else
		{
			status = pFun(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		}
	}
	else
	{
		status = pFun(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	}
	ObDereferenceObject(targetProcess);
	return status;
}


NTSTATUS FakeNtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
	)
{
	PEPROCESS currentProcess = NULL;
	currentProcess = PsGetCurrentProcess();
	PUCHAR szProcessName = NULL;
	szProcessName = PsGetProcessImageFileName(currentProcess);
	//
	KdPrint(("有进程尝试创建调试对象,进程名:%s\n", szProcessName));
	//永远返回失败
	return STATUS_UNSUCCESSFUL;
}


BOOLEAN  FakeKeInsertQueueApc(IN PKAPC Apc,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2,
	IN KPRIORITY PriorityBoost)
{
	PEPROCESS currentProcess = NULL;
	HANDLE currentProcessId = 0;
	PEPROCESS targetProcess = NULL;
	HANDLE targetProcessId = 0;
	PUCHAR szCurrentProcessName = NULL;
	BOOLEAN bRet = FALSE;

	fpTypeKeInsertQueueApc pFun = (fpTypeKeInsertQueueApc)g_inlineKeInsertQueueApc.pNewHookAddr;
	//获取当前进程的相关信息
	currentProcess = PsGetCurrentProcess();
	szCurrentProcessName = PsGetProcessImageFileName(currentProcess);
	currentProcessId = PsGetProcessId(currentProcess);

	//获取目标进程信息
	targetProcess = IoThreadToProcess(Apc->Thread);
	targetProcessId = PsGetProcessId(targetProcess);


	//开始保护了
	if ((HANDLE)g_needProtectObj.uGameProcessID != 0)
	{
		
		if ((HANDLE)g_needProtectObj.uGameProcessID == targetProcessId &&
			currentProcessId != targetProcessId
			)
		{
			KdPrint(("有进程尝试对保护进程插入apc,进程名字:%s\n", szCurrentProcessName));
			bRet = FALSE;
		}
		else
		{
			bRet = pFun(Apc, SystemArgument1, SystemArgument2, PriorityBoost);
		}
	}
	else
	{
		bRet = pFun(Apc, SystemArgument1, SystemArgument2, PriorityBoost);
	}
	return bRet;

}


NTSTATUS FakeKeUserModeCallback(
	IN ULONG ApiNumber,
	IN PVOID InputBuffer,
	IN ULONG InputLength,
	OUT PVOID *OutputBuffer,
	IN PULONG OutputLength
	)
{
	NTSTATUS status;
	PEPROCESS currentProcess = NULL;
	HANDLE currentProcessId = 0;

	fpTypeKeUserModeCallback pFun = (fpTypeKeUserModeCallback)g_inlineKeUserModeCallBack.pNewHookAddr;
	currentProcess = PsGetCurrentProcess();
	currentProcessId = PsGetProcessId(currentProcess);

	if (g_needProtectObj.uGameProcessID != 0)
	{
		//api==144 && InputLength = 0x90是消息钩子
		if ((HANDLE)g_needProtectObj.uGameProcessID == currentProcessId&& 0x41 == ApiNumber && 0x90 == InputLength)
		{
			KdPrint(("拦截到0x41处的消息钩子\n"));
			status = STATUS_UNSUCCESSFUL;
		}
		else
		{
			status = pFun(ApiNumber, InputBuffer, InputLength, OutputBuffer, OutputLength);
		}
	}
	else
	{
		status = pFun(ApiNumber, InputBuffer, InputLength, OutputBuffer, OutputLength);
	}
	return status;
}

NTSYSAPI SSDTEntry KeServiceDescriptorTable;
BOOLEAN FakeMmIsAddressValid(
	_In_  PVOID VirtualAddress
	)
{

	fpTypeMmIsAddressValid pFun = (fpTypeMmIsAddressValid)g_inlineMmIsAddressValid.pNewHookAddr;
	if (VirtualAddress == g_inlineKeInsertQueueApc.lpHookAddr ||
		VirtualAddress == g_inlineKeUserModeCallBack.lpFakeFuncAddr ||
		VirtualAddress == g_inlineMmIsAddressValid.lpHookAddr ||
		VirtualAddress == g_inlineNtCreateDebugObject.lpHookAddr ||
		VirtualAddress == g_inlineNtOpenProcess.lpHookAddr ||
		VirtualAddress == g_inlineKeStackAttachProcess.lpHookAddr ||
		VirtualAddress == g_inlineNtOpenThread.lpHookAddr ||
		VirtualAddress == g_inlineNtDuplicateObject.lpHookAddr ||
		KeServiceDescriptorTable.ServiceTableBase == VirtualAddress
		)
	{
		return FALSE;
	}
	return pFun(VirtualAddress);
}

NTSTATUS FakeNtUserFindWindowEx(
	IN HWND hwndParent,
	IN HWND hwndChild,
	IN PUNICODE_STRING pstrClassName OPTIONAL,
	IN PUNICODE_STRING pstrWindowName OPTIONAL,
	IN DWORD dwType)
{
	fpTypeNtUserFindWindowEx pFun = (fpTypeNtUserFindWindowEx)g_inlineNtUserFindWindowEx.pNewHookAddr;

	return pFun(hwndParent, hwndChild, pstrClassName, pstrWindowName, dwType);
}


ULONG FakeNtUserGetForegroundWindow(VOID)
{
	fpTypeNtUserGetForegroundWindow pFun = (fpTypeNtUserGetForegroundWindow)g_inlineNtUserGetForegroundWindow.pNewHookAddr;
	return pFun();
}


UINT_PTR FakeNtUserQueryWindow(IN ULONG WindowHandle, IN ULONG TypeInformation) //GetWindowThreadProcessId 获取句柄对应的进程PID
{
	fpTypeNtUserQueryWindow pFun = (fpTypeNtUserQueryWindow)g_inlineNtUserQueryWindow.pNewHookAddr;
	return pFun(WindowHandle, TypeInformation);
}


NTSTATUS  FakeNtUserPostMessage(
	IN HWND hWnd,
	IN ULONG pMsg,
	IN ULONG wParam,
	IN ULONG lParam
	)
{
	fpTypeNtUserPostMessage pFun = (fpTypeNtUserPostMessage)g_inlineNtUserPostMessage.pNewHookAddr;
	return pFun(hWnd, pMsg, wParam, lParam);
}

BOOL FakeNtUserPostThreadMessage(
	IN DWORD idThread,
	IN UINT Msg,
	IN ULONG wParam,
	IN ULONG lParam
	)
{
	fpTypeNtUserPostThreadMessage pFun = (fpTypeNtUserPostThreadMessage)g_inlineNtUserPostThreadMessage.pNewHookAddr;
	return pFun(idThread, Msg, wParam, lParam);
}

HHOOK FakeNtUserSetWindowsHookEx(
	HINSTANCE Mod,
	PUNICODE_STRING UnsafeModuleName,
	DWORD ThreadId,
	int HookId,
	PVOID HookProc,
	BOOL Ansi)
{
	fpTypeNtUserSetWindowsHookEx pFun = (fpTypeNtUserSetWindowsHookEx)g_inlineNtUserSetWindowsHookEx.pNewHookAddr;
	return pFun(Mod, UnsafeModuleName, ThreadId, HookId, HookProc, Ansi);
}


UINT FakeNtUserSendInput(
	IN UINT    cInputs,
	IN CONST INPUT *pInputs,
	IN int     cbSize
	)
{
	fpTypeNtUserSendInput pFun = (fpTypeNtUserSendInput)g_inlineNtUserSendInput.pNewHookAddr;
	return pFun(cInputs, pInputs, cbSize);
}


NTSTATUS FakeNtUserBuildHwndList(IN HDESK hdesk,
	IN HWND hwndNext,
	IN ULONG fEnumChildren,
	IN DWORD idThread,
	IN UINT cHwndMax,
	OUT HWND *phwndFirst,
	OUT ULONG* pcHwndNeeded)
{
	fpTypeNtUserBuildHwndList pFun = (fpTypeNtUserBuildHwndList)g_inlineNtUserBuildHwndList.pNewHookAddr;
	return pFun(hdesk, hwndNext, fEnumChildren, idThread, cHwndMax, phwndFirst, pcHwndNeeded);
}
