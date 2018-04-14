#pragma once

//xx_xx_xx_to_game: to_game代表内核发送给游戏
//xx_xx_xx_to_driver:to_driver代表游戏发送给内核
//结构体和字段全部使用小写,至于原因我是突然想起以前写游戏的时候协议定义了

#define  MAX_MSG_NUM 10
#define MAX_CHEAT_BUFF_SIZE 512

typedef struct __MsgNode
{
	struct __MsgNode* next;
	int nMsgNo;
	char buff[MAX_CHEAT_BUFF_SIZE];
}MsgNode;

#pragma pack(1)

#define HEARTBEAT_PACKET_TO_GAME 0 //驱动发送给游戏的心跳包
typedef struct _heartbeat_packet_to_game
{
	int ticket_count;
}heartbeat_packet_to_game;


//通知游戏退出
#define  EXIT_CODE_TO_GAME 1  //消息号
typedef struct _notify_game_exit
{
#define  EXIT_REASON_FOR_ARK_TOOL 1   //检测到ark工具
#define  EXIT_REASON_FOR_DEBUG_GAME 2 //检测到尝试调试游戏

	int game_exit_code;
}notify_exit_to_game;


//发送用户层可读事件给内核
#define  SEND_READ_ABLE_EVENT_HANDLE 2 //消息号
typedef struct _send_event_handle
{
	int event_handle;
}send_read_able_event_to_driver;

//发送给内核层需要保护的线程和进程
#define  SEND_NEED_PROTECTED_THREAD_PROCESS 3//消息号
typedef struct _send_need_protected_process
{
	int process_id;
	int rcv_msg_thread_id;
	int beart_thread_id;
}send_need_protected_process_to_driver;

#pragma pack()