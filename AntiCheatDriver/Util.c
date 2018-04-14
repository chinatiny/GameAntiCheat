#include "Util.h"

#define DELAY_ONE_MICROSECOND (-10)
#define DELAY_ONE_MILLISECOND (DELAY_ONE_MICROSECOND*1000)

void OffMemProtect()
{
	__asm { //关闭内存保护
		cli;
		push eax;
		mov eax, cr0;
		and eax, ~0x10000;
		mov cr0, eax;
		pop eax;
	}
}
void OnMemProtect()
{
	__asm { //恢复内存保护
		push eax;
		mov eax, cr0;
		or eax, 0x10000;
		mov cr0, eax;
		pop eax;
		sti;
	}
}

PLDR_DATA_TABLE_ENTRY FindModule(PDRIVER_OBJECT pDriver, PWCHAR pszDriverName)
{
	PLDR_DATA_TABLE_ENTRY pLdr =(PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	LIST_ENTRY *pTemp = &pLdr->InLoadOrderLinks;
	do
	{
		PLDR_DATA_TABLE_ENTRY pDriverInfo = (PLDR_DATA_TABLE_ENTRY)pTemp;

		if (wcsstr(pDriverInfo->BaseDllName.Buffer, pszDriverName))
		{
			return pDriverInfo;
		}
		pTemp = pTemp->Blink;
	} while (pTemp != &pLdr->InLoadOrderLinks);
	return NULL;
}

void Sleep(unsigned long msec)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
	return;
}


void Reboot()
{
	__asm
	{
		xor eax, eax;
		mov al, 0xFE;
		out 0x64, al;
	}
}



void  CleanDebugportByPID(HANDLE ProcessId)
{
	PEPROCESS EProcess;
	PVOID PDebugObject;
	PsLookupProcessByProcessId(ProcessId, &EProcess);
	PDebugObject = PsGetProcessDebugPort(EProcess);
	if (PDebugObject)
	{
		//这个偏移是win732位的
		*(PULONG)((SIZE_T)EProcess + 0x0ec) = 0;
	}
}


PETHREAD LookupThread(HANDLE hTid)
{
	PETHREAD pEThread = NULL;
	if (NT_SUCCESS(PsLookupThreadByThreadId(
		hTid,
		&pEThread)))
		return pEThread;
	return NULL;
}

PEPROCESS LookupProcess(HANDLE hPid)
{
	PEPROCESS pEProcess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(
		hPid, &pEProcess)))
		return pEProcess;
	return NULL;
}

void CleanTebDebugHandle()
{
	PETHREAD  pEThrd = NULL;
	ULONG i = 0;
	for (i = 4; i < 0x25600; i += 4) {
		pEThrd = LookupThread((HANDLE)i);
		if (!pEThrd)  continue;

		//0x088 teb是win732位的偏移
		ULONG  uTebAddr = *(PULONG)((SIZE_T)pEThrd + 0x88);
		if (MmIsAddressValid((PVOID)uTebAddr) &&
			MmIsAddressValid((PVOID)(uTebAddr + 0xf24))
			)
		{
			*(PULONG)((SIZE_T)uTebAddr + 0xf24) = 0;
		}
		ObDereferenceObject(pEThrd);
	}
}

