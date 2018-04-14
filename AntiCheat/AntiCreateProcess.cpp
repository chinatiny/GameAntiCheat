#include "AntiCreateProcess.h"
#include <Psapi.h>
#include "PEOperation.h"


#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)


//////////////////////////////内部函数///////////////////////////////////////
static DWORD s_dwSelfID = 0; //当前进程id
static DWORD s_dwExplorerProcessID = 0; //父进程id
static bool s_bSuspendCreateProcess = false;

//
static bool EnumProcessFunc(IN  void *callBackParameter, IN PROCESSENTRY32* pProcessEntry)
{
	if (pProcessEntry->th32ProcessID == s_dwSelfID)
	{
		if (pProcessEntry->th32ParentProcessID != s_dwExplorerProcessID)
		{
			s_bSuspendCreateProcess = true;
			return true;
		}
	}
	return false;
}



BOOL IsProcessType(HANDLE hHandle)
{
	NTSTATUS nsQuery;
	BOOL bRet = TRUE;
	POBJECT_TYPE_INFORMATION obTypeInfo = NULL;
	obTypeInfo = (POBJECT_TYPE_INFORMATION)VirtualAlloc(NULL, sizeof(OBJECT_TYPE_INFORMATION)+0x1000, MEM_COMMIT, PAGE_READWRITE);
	nsQuery = ZwQueryObject(hHandle, ObjectTypeInformation, obTypeInfo, sizeof(OBJECT_TYPE_INFORMATION)+0x1000, NULL);
	if (NT_SUCCESS(nsQuery))
	{
		if (_wcsicmp(obTypeInfo->TypeName.Buffer, L"Process") != 0)
		{
			bRet = FALSE;
		}
	}
	VirtualFree(obTypeInfo, 0, MEM_RELEASE);
	return bRet;
}
HANDLE DumpHandle(HANDLE hProcessId, HANDLE hHandleValue)
{
	HANDLE hRet = 0;
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS nsProcess;
	HANDLE hProcess;
	CLIENT_ID ProcessId = { 0 };
	ProcessId.UniqueProcess = hProcessId;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	nsProcess = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &ProcessId);

	if (NT_SUCCESS(nsProcess))
	{
		TCHAR szFileName[MAX_PATH] = { 0 };
		GetProcessImageFileName(hProcess, szFileName, _countof(szFileName));
		PathStripPath(szFileName);


		if (!_tcscmp(szFileName, _T("csrss.exe")) ||
			!_tcscmp(szFileName, _T("lsass.exe")) ||
			!_tcscmp(szFileName, _T("svchost.exe")) ||
			!_tcscmp(szFileName, _T("explorer.exe")))
		{
			return NULL;
		}

		NTSTATUS nsDup;
		HANDLE hLocalHandle;
		nsDup = ZwDuplicateObject(
			hProcess,
			hHandleValue,
			GetCurrentProcess(),
			&hLocalHandle,
			0L,
			0L,
			DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES
			);//进行对象复制
		if (NT_SUCCESS(nsDup))
		{
			//这里准备查询！
			hRet = hLocalHandle;
		}
		_tprintf(TEXT("找到一个\n"));
		CloseHandle(hProcess);
	}
	return hRet;
}

VOID KillHandle(HANDLE hProcessId, HANDLE hHandleValue)
{
	if (GetCurrentProcessId() == (DWORD)hProcessId)
	{
		return;
	}

	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS nsProcess;
	HANDLE hProcess;
	CLIENT_ID ProcessId = { 0 };
	ProcessId.UniqueProcess = hProcessId;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	nsProcess = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &ProcessId);
	if (NT_SUCCESS(nsProcess))
	{
		NTSTATUS nsDup;
		HANDLE hLocalHandle;
		nsDup = ZwDuplicateObject(
			hProcess,
			hHandleValue,
			GetCurrentProcess(),
			&hLocalHandle,
			0L,
			0L,
			DUPLICATE_CLOSE_SOURCE
			);//进行对象Kill
		if (NT_SUCCESS(nsDup))
		{
			CloseHandle(hLocalHandle);
		}
		CloseHandle(hProcess);
	}
	return;
}

DWORD WINAPI KillHandleThread(LPVOID lparam)
{
	while (1)
	{
		NTSTATUS ns;
		ULONG nSize = 0;
		ns = ZwQuerySystemInformation(SystemHandleInformation, NULL, 0, &nSize);
		if (ns == STATUS_INFO_LENGTH_MISMATCH)
		{
			//////////////////////////////////////////////////////////////////////////
			//首先通过NULL参数获取Buffer的大小,然后申请Buffer
			//////////////////////////////////////////////////////////////////////////
		Loop:
			PVOID pBuffer = NULL;
			pBuffer = VirtualAlloc(NULL, nSize * 2, MEM_COMMIT, PAGE_READWRITE);//如果在内核形态这里是使用Pool或者其他内核内存分配形态！！！
			if (pBuffer)
			{
				RtlZeroMemory(pBuffer, nSize * 2);
				ns = ZwQuerySystemInformation(SystemHandleInformation, pBuffer, nSize * 2, NULL);
				if (NT_SUCCESS(ns))
				{
					//////////////////////////////////////////////////////////////////////////
					//第二次调用获取Handle成功了，这里开始写遍历了！！！
					//////////////////////////////////////////////////////////////////////////
					ULONG nIndex = 0;
					PSYSTEM_HANDLE_INFORMATION pSysinfo = NULL;
					pSysinfo = (PSYSTEM_HANDLE_INFORMATION)pBuffer;
					for (nIndex = 0; nIndex < pSysinfo->NumberOfHandles; nIndex++)
					{
						if (pSysinfo->Handles[nIndex].UniqueProcessId != GetCurrentProcessId())
						{
							//不是本进程的东西，则先打开目标进程！
							HANDLE hLocalHandle = DumpHandle((HANDLE)pSysinfo->Handles[nIndex].UniqueProcessId, (HANDLE)pSysinfo->Handles[nIndex].HandleValue);
							if (hLocalHandle)
							{
								if (IsProcessType(hLocalHandle))
								{
									TCHAR szFileName[MAX_PATH] = { 0 };
									GetProcessImageFileName(hLocalHandle, szFileName, MAX_PATH);
									if (GetProcessId(hLocalHandle) == GetCurrentProcessId())
									{
										KillHandle((HANDLE)pSysinfo->Handles[nIndex].UniqueProcessId, (HANDLE)pSysinfo->Handles[nIndex].HandleValue);
									}
								}
								CloseHandle(hLocalHandle);
							}
						}
						else
						{
							if (pSysinfo->Handles[nIndex].UniqueProcessId != GetCurrentProcessId())
							{
								if (IsProcessType((HANDLE)pSysinfo->Handles[nIndex].HandleValue))
								{
									CloseHandle((HANDLE)pSysinfo->Handles[nIndex].HandleValue);
								}
							}

						}
					}
				}
				VirtualFree(pBuffer, 0, MEM_RELEASE);//释放内存
				if (ns == STATUS_INFO_LENGTH_MISMATCH)//如果是内存不够，则扩大10倍继续申请！！
				{
					nSize = nSize * 10;
					goto Loop;
				}
			}
		}
		Sleep(1000);
	}
	return 0;
}


//////////////////////////////对外接口///////////////////////////////////////
//检测父进程
void CheckSuspendCreateProcess()
{
	//检测父进程
	s_dwSelfID = GetCurrentProcessId();
	GetWindowThreadProcessId(FindWindow(TEXT("Progman"), NULL), &s_dwExplorerProcessID);
	EnumProcess(EnumProcessFunc, NULL);
}

//清理掉在别的进程的句柄
void ClearSelfHandleInOtherProcess()
{
	CreateThread(NULL, 0, KillHandleThread, NULL, 0, NULL);
}

bool IsSuspendProcess()
{
	return s_bSuspendCreateProcess;
}


