#pragma  once
#include "AntiCheatDriver.h"
#include "UnDocoumentSpec.h"

void OffMemProtect();
void OnMemProtect();
PLDR_DATA_TABLE_ENTRY FindModule(PDRIVER_OBJECT pDriver, PWCHAR pszDriverName);
void Sleep(unsigned long msec);

PETHREAD LookupThread(HANDLE hTid);
PEPROCESS LookupProcess(HANDLE hPid);

//重启电脑
void Reboot();

//清空调试端口
void CleanDebugportByPID(IN HANDLE ProcessId);

//清空teb的f24
void CleanTebDebugHandle();