#include "Timer.h"
#include "Packet.h"
#include "AntiWorker.h"
#include "ProcessProtected.h"

ULONG  g_uKdEnableFlagAddr = 0;

void GetEnableFlagAddr()
{
	UNICODE_STRING funcName;
	RtlInitUnicodeString(&funcName, L"KdDisableDebugger");
	ULONG step = 0;
	ULONG targetFunAddr = 0;
	ULONG baseFunAddr = (ULONG)MmGetSystemRoutineAddress(&funcName);
	for (step = baseFunAddr; step < (baseFunAddr + 1024); step++)
	{
		//搜索：0x6A,0x01, 0xE8
		if (((*(PUCHAR)(UCHAR*)(step - 1)) == 0xE8) &&
			((*(PUCHAR)(UCHAR*)(step - 2)) == 0x01) &&
			((*(PUCHAR)(UCHAR*)(step - 3)) == 0x6A))
		{
			ULONG offset = *(PULONG)step;
			targetFunAddr = (ULONG)(step - 3) + offset + 5;
			break;
		}
	}
	KdPrint(("step1 addr:%08X\n", targetFunAddr));
	if (targetFunAddr != 0)
	{
		baseFunAddr = targetFunAddr;
		for (step = baseFunAddr; step < (baseFunAddr + 1024); step++)
		{
			//搜索：0x75, 0x5C,0xA0
			if (((*(PUCHAR)(UCHAR*)(step - 1)) == 0xA0) &&
				((*(PUCHAR)(UCHAR*)(step - 2)) == 0x5C) &&
				((*(PUCHAR)(UCHAR*)(step - 3)) == 0x75))
			{
				targetFunAddr = *(PULONG)step;
				break;
			}
		}
	}
	g_uKdEnableFlagAddr = targetFunAddr;
}


VOID TimerProc(struct _DEVICE_OBJECT *pDevice, PVOID Context)
{
	if (g_needProtectObj.uGameProcessID != 0)
	{
		//插入心跳包
		static int nCount = 0;
		MsgNode *node = MakeMsgNode(HEARTBEAT_PACKET_TO_GAME);
		heartbeat_packet_to_game* pSt = (heartbeat_packet_to_game*)node->buff;
		pSt->ticket_count = nCount++;
		InsertMsgQue(&g_outQue, node);
		//反双机调试
		if (g_uKdEnableFlagAddr)
		{
			*(PULONG)g_uKdEnableFlagAddr = 0;
		}
	}

}
