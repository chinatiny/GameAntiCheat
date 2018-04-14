#pragma  once
#include "AntiCheat.h"

//退出进程hook
VOID OnHookExitProcess();
VOID OnHookWnd();
VOID OnIsWindow();  //这个是mfc框架比较明显的函数