#pragma once
#include "AntiCheat.h"
#include "ProcessOperation.h"

//检测以阻塞的方式启动进程然后shellcode注入
void CheckSuspendCreateProcess();

//清理句柄
void ClearSelfHandleInOtherProcess();
//判断是否是非正常方式启动
bool IsSuspendProcess();
