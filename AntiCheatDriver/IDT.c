#include "IDT.h"
#include "UnDocoumentSpec.h"

#pragma warning(disable:4305)

#define  TRAP_01  0x1
#define  TRAP_03 0x3
#pragma pack(1)
typedef struct _IDT
{
	short Limit;
	unsigned int Base;
}IDT, *PIDT;

typedef struct _IDTENTRY
{
	unsigned short OffsetLow;
	unsigned short Selector;
	unsigned char  Reserved;
	unsigned char  Type : 4;
	unsigned char  Reserved0 : 1;
	unsigned char  Dpl : 2;
	unsigned char  Present : 1;
	unsigned short OffsetHigh;
}IDTENTRY, *PIDTENTRY;
#pragma pack()

typedef KAFFINITY(*fpTypeKeSetAffinityThread)(
	__inout PKTHREAD Thread,
	__in KAFFINITY Affinity
	);

UCHAR    g_idtBuffer[6] = { 0 };
IDTENTRY g_oldTrap01Entry = { 0 };
IDTENTRY g_oldTrap03Entry = { 0 };

#pragma  LOCKEDCODE
void _declspec(naked)FakeTrap01()
{
	//清除调试寄存器
	__asm
	{
		xor eax, eax;
		mov dr0, eax;
		mov dr1, eax;
		mov dr2, eax;
		mov dr3, eax;
		mov eax, 0x9B;
		mov dr7, eax;
		iretd;
	}
}

void __declspec(naked) FakeTrap03()
{
	__asm
	{
		iretd;
	}
}

#pragma  PAGEDCODE
void InstallIDTHook()
{
	ULONG Index, Affinity, CurrentAffinity;
	ULONG fnpKeSetAffinityThread;
	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, L"KeSetAffinityThread");
	fnpKeSetAffinityThread = (ULONG)MmGetSystemRoutineAddress(&funcName);
	Affinity = KeQueryActiveProcessors();

	CurrentAffinity = 1;
	Index = 0;
	while (Affinity)
	{
		//下面只是个简单的算法，使当前线程运行到不同的处理器上
		Affinity &= ~CurrentAffinity;
		((fpTypeKeSetAffinityThread)fnpKeSetAffinityThread)(PsGetCurrentThread(), (KAFFINITY)CurrentAffinity);
		CurrentAffinity <<= 1;

		//针对该核
		PIDT idt = (PIDT)g_idtBuffer;
		PIDTENTRY idtArry;
		__asm
		{
			pushfd;
			cli;
			sidt g_idtBuffer;
		}
		idtArry = (PIDTENTRY)idt->Base;
		memcpy(&g_oldTrap01Entry, idtArry + TRAP_01, sizeof(IDTENTRY));
		memcpy(&g_oldTrap03Entry, idtArry + TRAP_03, sizeof(IDTENTRY));

		idtArry[TRAP_01].OffsetLow = (unsigned short)FakeTrap01;
		idtArry[TRAP_01].Selector = g_oldTrap01Entry.Selector;
		idtArry[TRAP_01].Reserved = g_oldTrap01Entry.Reserved;
		idtArry[TRAP_01].Type = g_oldTrap01Entry.Type;
		idtArry[TRAP_01].Reserved0 = g_oldTrap01Entry.Reserved0;
		idtArry[TRAP_01].Dpl = g_oldTrap01Entry.Dpl;
		idtArry[TRAP_01].Present = g_oldTrap01Entry.Present;
		idtArry[TRAP_01].OffsetHigh = (unsigned short)((unsigned int)FakeTrap01 >> 16);

		idtArry[TRAP_03].OffsetLow = (unsigned short)FakeTrap03;
		idtArry[TRAP_03].Selector = g_oldTrap03Entry.Selector;
		idtArry[TRAP_03].Reserved = g_oldTrap03Entry.Reserved;
		idtArry[TRAP_03].Type = g_oldTrap03Entry.Type;
		idtArry[TRAP_03].Reserved0 = g_oldTrap03Entry.Reserved0;
		idtArry[TRAP_03].Dpl = g_oldTrap03Entry.Dpl;
		idtArry[TRAP_03].Present = g_oldTrap03Entry.Present;
		idtArry[TRAP_03].OffsetHigh = (unsigned short)((unsigned int)FakeTrap03 >> 16);
		__asm
		{
			sti;
			popfd;
		}
	}
}


void UnistallIDTHook()
{
	ULONG Index, Affinity, CurrentAffinity;
	ULONG fnpKeSetAffinityThread;
	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, L"KeSetAffinityThread");
	fnpKeSetAffinityThread = (ULONG)MmGetSystemRoutineAddress(&funcName);
	Affinity = KeQueryActiveProcessors();

	CurrentAffinity = 1;
	Index = 0;
	while (Affinity)
	{
		//下面只是个简单的算法，使当前线程运行到不同的处理器上
		Affinity &= ~CurrentAffinity;
		((fpTypeKeSetAffinityThread)fnpKeSetAffinityThread)(PsGetCurrentThread(), (KAFFINITY)CurrentAffinity);
		CurrentAffinity <<= 1;

		PIDT idt = (PIDT)g_idtBuffer;
		PIDTENTRY idtArry;
		__asm
		{
			pushfd;
			cli;
			sidt g_idtBuffer;
		}
		idtArry = (PIDTENTRY)idt->Base;
		memcpy(idtArry + TRAP_01, &g_oldTrap01Entry, sizeof(IDTENTRY));
		memcpy(idtArry + TRAP_03, &g_oldTrap03Entry, sizeof(IDTENTRY));
		__asm
		{
			sti;
			popfd;
		}
	}
}
