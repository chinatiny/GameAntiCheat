#pragma once
#include "AntiCheatDriver.h"

#pragma pack(1)
typedef struct _ServiceDesriptorEntry
{
	ULONG *ServiceTableBase;        // 服务表基址
	ULONG *ServiceCounterTableBase; // 计数表基址
	ULONG NumberOfServices;         // 表中项的个数
	UCHAR *ParamTableBase;          // 参数表基址
}SSDTEntry, *PSSDTEntry;
#pragma pack()

// 导入SSDT
NTSYSAPI SSDTEntry KeServiceDescriptorTable;

//通过名字获取ssdt的序号
int  GetSSDTOrderByName(const char* szFuncName);

//通过名字获取ssdt表中的函数地址
PVOID GetSSDTFuncAddrByName(const char* szFuncName);


