#pragma  once

#include <ntifs.h>
#include <ntimage.h>
#include <minwindef.h>
#include "../AntiCheat/CheatMsg.h"
#include "InlineHook.h"
#include "SSDT.h"
#pragma warning(disable:4189 4100 4201 4706 4127 4057 4055 4214 4152)

#define  DEVICE_NAME L"\\Device\\AntiGameCheat"
#define  SYSBOL_LINK_NAME L"\\DosDevices\\AntiGameCheat"
#define	 EXALLOC_POOL_TAG		' ct'

#define PAGEDCODE code_seg("PAGE")  
#define LOCKEDCODE code_seg()  
#define INITCODE code_seg("INIT")  

#define PAGEDDATA data_seg("PAGE")  
#define LOCKEDDATA data_seg()  
#define INITDATA data_seg("INIT") 

//需要保护的内核对象
typedef struct _NeedProtectedObj
{
	ULONG uRcvMsgThreadID;
	ULONG uCheckHeartThreadID;
	ULONG uGameProcessID;
}NeedProtectedObj;