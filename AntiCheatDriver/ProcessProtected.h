#pragma once
#include "AntiCheatDriver.h"

//卸载保护
void UnRegisterProtected();
//设置需要保护的对象
void SetProcessProtected(ULONG uRcvMsgThreadID, ULONG uCheckHeartThreadID, ULONG uProcessID);

extern NeedProtectedObj g_needProtectObj;

VOID ProcessNotifyRoutine(
	IN HANDLE        ParentId,
	IN HANDLE        ProcessId,
	IN BOOLEAN        Create
	);

