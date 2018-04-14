#pragma once
#include "AntiCheat.h"

void Router(char* buff, int nRcvSize);

//ÐÄÌø°ü¼ì²é
typedef struct _HearbtBeatCheckSt
{
	int nLastTicket;
	DWORD dwSysTicketCount;
}HearbtBeatCheckSt;
void CheckHeartBeat(int nNewTicket);
unsigned int __stdcall CheckHearbeat(void* pArg);