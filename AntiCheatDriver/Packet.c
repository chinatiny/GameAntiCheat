#include "Packet.h"
#include "Util.h"
extern int GetMsgSize(int nMsgNo);
extern AntiCheatMsgQue g_outQue;

VOID InitMsgQue(AntiCheatMsgQue *pMsgQue)
{
	KeInitializeSpinLock(&pMsgQue->spinMsgQue);
	pMsgQue->root.nMsgNo = -1;
	pMsgQue->root.next = NULL;
	pMsgQue->fist = &pMsgQue->root;
	pMsgQue->last = &pMsgQue->root;
}

VOID InsertMsgQue(AntiCheatMsgQue *pMsgQue, MsgNode *node)
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&pMsgQue->spinMsgQue, &oldIrql);
	node->next = NULL;
	pMsgQue->last->next = node;
	pMsgQue->last = node;

	//如果是第一次插入
	if (pMsgQue->fist == &pMsgQue->root)
	{
		pMsgQue->fist = node;
	}
	KeReleaseSpinLock(&pMsgQue->spinMsgQue, oldIrql);
}

MsgNode* PopMsgQue(AntiCheatMsgQue *pMsgQue)
{
	MsgNode *node = NULL;
	KIRQL oldIrql;
	KeAcquireSpinLock(&pMsgQue->spinMsgQue, &oldIrql);

	if (pMsgQue->fist == &pMsgQue->root)
	{
		node = NULL;
	}
	else
	{
		node = pMsgQue->fist;
		pMsgQue->root.next = pMsgQue->fist->next;
		//
		if (pMsgQue->root.next)
		{
			pMsgQue->fist = pMsgQue->root.next;
		}
		else
		{
			pMsgQue->fist = &pMsgQue->root;
			pMsgQue->last = &pMsgQue->root;
		}

	}
	KeReleaseSpinLock(&pMsgQue->spinMsgQue, oldIrql);
	return node;
}

BOOLEAN IsMsgQueEmpty(AntiCheatMsgQue *pMsgQue)
{
	BOOLEAN bRet = FALSE;
	KIRQL oldIrql;
	KeAcquireSpinLock(&pMsgQue->spinMsgQue, &oldIrql);
	bRet = (pMsgQue->fist == &pMsgQue->root);
	KeReleaseSpinLock(&pMsgQue->spinMsgQue, oldIrql);
	return bRet;
}

VOID CleanMsgQue(AntiCheatMsgQue *pMsgQue)
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&pMsgQue->spinMsgQue, &oldIrql);

	MsgNode *node = pMsgQue->fist;
	if (node == &pMsgQue->root)
		return;
	//
	while (node)
	{
		MsgNode *pre = node;
		node = node->next;
		//
		ExFreePool(pre);
	}
	pMsgQue->fist = &pMsgQue->root;
	pMsgQue->last = &pMsgQue->root;

	KeReleaseSpinLock(&pMsgQue->spinMsgQue, oldIrql);
}


MsgNode* MakeMsgNode(int nMsgNo)
{
	MsgNode *node = NULL;
	int nStSize = GetMsgSize(nMsgNo);
	if (-1 == nStSize)
		return NULL;

	node = ExAllocatePool(NonPagedPool, sizeof(MsgNode));
	if (NULL == node)
		return NULL;

	node->nMsgNo = nMsgNo;
	return node;
}

//通知游戏退出
VOID ExitGame(int nExitGame)
{
	MsgNode *node = MakeMsgNode(EXIT_CODE_TO_GAME);
	if (NULL != node)
	{
		notify_exit_to_game* pst = (notify_exit_to_game*)node->buff;
		pst->game_exit_code = nExitGame;
		InsertMsgQue(&g_outQue, node);
	}
}
