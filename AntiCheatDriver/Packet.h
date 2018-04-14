#pragma once
#include "AntiCheatDriver.h"

//消息结构体

typedef struct __AntiCheatMsgQue
{
	KSPIN_LOCK spinMsgQue;
	MsgNode root;
	MsgNode* fist; //第一个指针的位置
	MsgNode* last; //最后一个指针的位置
}AntiCheatMsgQue;

//初始化输出队列
VOID InitMsgQue(AntiCheatMsgQue *pMsgQue);
//插入队列
VOID InsertMsgQue(AntiCheatMsgQue *pMsgQue, MsgNode *node);
//出队列
MsgNode* PopMsgQue(AntiCheatMsgQue *pMsgQue);
//判断是否为空
BOOLEAN IsMsgQueEmpty(AntiCheatMsgQue *pMsgQue);
//清理所有数据
VOID CleanMsgQue(AntiCheatMsgQue *pMsgQue);

//创建一个MsgNode的节点
MsgNode* MakeMsgNode(int nMsgNo);


//通知游戏退出
VOID ExitGame(int nExitGame);