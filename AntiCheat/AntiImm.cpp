#include "AntiImm.h"
#include "AntiCheat.h"
#include <windows.h>
#include <tchar.h>
#include <imm.h>
#include "detours/detours.h"

#pragma comment(lib,"detours/lib.X86/detours.lib")


///////////////对内接口
typedef BOOL (WINAPI *fpTypeImmGetHotKey)(
	DWORD dwHotKeyID,
	LPUINT lpuModifiers,
	LPUINT lpuVKey,
	LPHKL lphKL
	);
typedef int(__stdcall *fpTypeImmActivateLayout)(LPARAM);

fpTypeImmGetHotKey s_fpGetHotKey = NULL;
fpTypeImmActivateLayout s_fpImmActivateLayout = NULL;
bool s_bActiveFlag = false;



BOOL WINAPI MyImmGetHotKey(
	DWORD dwHotKeyID,
	LPUINT lpuModifiers,
	LPUINT lpuVKey,
	LPHKL lphKL
	)
{
	s_bActiveFlag = true;
	return s_fpGetHotKey(dwHotKeyID, lpuModifiers, lpuVKey, lphKL);
}


int __stdcall MyImmActivateLayout(LPARAM pa)
{
	if (s_bActiveFlag)
	{
		s_bActiveFlag = true;
	}
	else
	{
		MessageBox(NULL, _T("检测到输入法注入"), _T("提示"), MB_OK);
		ExitProcess(5);
	}
	return s_fpImmActivateLayout(pa);
}

//对外接口
void MonitorImme()
{
	HMODULE hImm32 = LoadLibrary(_T("imm32.dll"));
	fpTypeImmGetHotKey g_fpGetHotKey = (fpTypeImmGetHotKey)GetProcAddress(hImm32, "ImmGetHotKey");
	fpTypeImmActivateLayout g_fpImmActivateLayout = (fpTypeImmActivateLayout)GetProcAddress(hImm32, "ImmActivateLayout");

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((PVOID*)&s_fpGetHotKey, MyImmGetHotKey);
	DetourAttach((PVOID*)&s_fpImmActivateLayout, MyImmActivateLayout);
	DetourTransactionCommit();
}
