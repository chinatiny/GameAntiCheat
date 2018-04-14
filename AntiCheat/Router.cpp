#include "Router.h"
#include "GameHack.h"

//检查时钟
HearbtBeatCheckSt g_hbCheckSt = { 0, 0 };

//从驱动接收到退出游戏请求
void HandleGameExit(notify_exit_to_game* pMsg);
//接收来自驱动的心跳包
void HandleHeartbeat(heartbeat_packet_to_game* pMsg);


void Router(char* buff, int nRcvSize)
{
	MsgNode* node = (MsgNode*)buff;
	char *stBuff = node->buff;
	switch (node->nMsgNo)
	{
	case EXIT_CODE_TO_GAME:
		HandleGameExit((notify_exit_to_game*)stBuff);
		break;
	case HEARTBEAT_PACKET_TO_GAME:
		HandleHeartbeat((heartbeat_packet_to_game*)stBuff);
		break;
	default:
		break;
	}
}


void CheckHeartBeat(int nNewTicket)
{
	PrintDbgInfo(_T("来自驱动的心跳：%d"), nNewTicket);
	DWORD dwNowTicket = GetTickCount();
	if (0 == g_hbCheckSt.nLastTicket && 0 == g_hbCheckSt.dwSysTicketCount)
	{
		g_hbCheckSt.nLastTicket = nNewTicket;
		g_hbCheckSt.dwSysTicketCount = dwNowTicket;
	}
	else
	{
		DWORD dwSec = (dwNowTicket - g_hbCheckSt.dwSysTicketCount) / 1000;
		if (dwSec > 10)
		{
			MyExitGame(1);
		}
		//
		g_hbCheckSt.nLastTicket = nNewTicket;
		g_hbCheckSt.dwSysTicketCount = dwNowTicket;
	}
}

void HandleGameExit(notify_exit_to_game* pMsg)
{
	PrintDbgInfo(_T("退出代码为:%d"), pMsg->game_exit_code);
	MyExitGame(pMsg->game_exit_code);
}

void HandleHeartbeat(heartbeat_packet_to_game* pMsg)
{
	CheckHeartBeat(pMsg->ticket_count);
}


unsigned int __stdcall CheckHearbeat(void* pArg)
{
	while (true)
	{
		Sleep(1000);
		DWORD dwNowTicket = GetTickCount();
		DWORD dwSec = (dwNowTicket - g_hbCheckSt.dwSysTicketCount) / 1000;
		if (dwSec > 10)
		{
			MyExitGame(1);
		}
	}
	return 0;
}