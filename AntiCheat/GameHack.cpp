#include "GameHack.h"
#include "AntiCheat.h"


BYTE g_byHackCode1[] = {0x50, 0xFF, 0x35, 0x8C, 0x37, 0x49, 0x00, 0x8D, 0x45, 0x9C, 0x50, 0x8D, 0x45, 0x90, 0x50, 0x8D, 0x45, 0xA0, 0x50 };
SIZE_T g_stHackCode1Offset = 0xA2 + 0x38048;

void GameHack()
{
	HMODULE hExe = GetModuleHandle(NULL);
	LPVOID lpHackAddr = (LPVOID)((SIZE_T)hExe + g_stHackCode1Offset);

	DWORD dwOldProtected;
	VirtualProtect(lpHackAddr, sizeof(g_byHackCode1), PAGE_EXECUTE_READWRITE, &dwOldProtected);
	memcpy(lpHackAddr, g_byHackCode1, sizeof(g_byHackCode1));
	VirtualProtect(lpHackAddr, sizeof(g_byHackCode1), dwOldProtected, &dwOldProtected);
}

void MyExitGame(int nExitStatus)
{
	PrintDbgInfo(_T("ÍË³öÂëÎª:%d\n"), nExitStatus);
	Sleep(100000);
	ExitProcess(nExitStatus);
}
