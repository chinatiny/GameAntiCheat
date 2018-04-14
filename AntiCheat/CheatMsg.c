#include "CheatMsg.h"

 int GetMsgSize(int nMsgNo)
{
	switch (nMsgNo)
	{
	case HEARTBEAT_PACKET_TO_GAME:
		return sizeof(heartbeat_packet_to_game);
	case EXIT_CODE_TO_GAME:
		return sizeof(notify_exit_to_game);
	case SEND_READ_ABLE_EVENT_HANDLE:
		return sizeof(send_read_able_event_to_driver);
	case SEND_NEED_PROTECTED_THREAD_PROCESS:
		return sizeof(send_need_protected_process_to_driver);
	}
	return -1;
}
