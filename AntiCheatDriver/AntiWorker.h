#pragma once
#include "AntiCheatDriver.h"
#include "Packet.h"

//应用层用来接收数据的同步事件
extern PKEVENT g_pReadAbleEvent; 
extern KSPIN_LOCK g_spinWorkState;
extern CLIENT_ID g_workClientID;
extern AntiCheatMsgQue g_outQue;
extern VOID WorkerThread(IN PVOID StartContext);


//设置工作状态
VOID SetWorkState(BOOLEAN bWorkState);
//脏读取工作状态
BOOLEAN DirtyReadWorkState();


//工作主线程
VOID WorkerThread(IN PVOID StartContext);