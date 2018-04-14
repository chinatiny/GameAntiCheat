#pragma once
#include "AntiCheatDriver.h"

VOID TimerProc(DEVICE_OBJECT *DeviceObject, PVOID Context);
#pragma alloc_text(NONE_PAGE,TimerProc)

//获取反内核调试的地址
void GetEnableFlagAddr();


