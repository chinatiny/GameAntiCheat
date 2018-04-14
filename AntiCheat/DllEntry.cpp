#include "AntiCheat.h"
#include "DllEntry.h"
#include "AntiCheateMain.h"

#pragma comment ( lib,"User32.lib" ) 

HMODULE g_hModule = NULL;

BOOL APIENTRY DllMain(
	HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		g_hModule = hModule;
		AntiCheatMain();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

//没用使用
int TestFuncName()
{
	return 1;
}
