#include "GameHook.h"
#include "DriverOperation.h"

///////////////////////////////////////////////退出进程hook////////////////////////////////////////////////////////////////////
typedef VOID (WINAPI *fpTypeExitProcess)( _In_  UINT uExitCode);
fpTypeExitProcess g_fpOldExitProcess = NULL;
VOID WINAPI MyExitProcess(_In_  UINT uExitCode)
{
	//在进程退出之前做点事情
	g_fpOldExitProcess(uExitCode);
}

VOID OnHookExitProcess()
{
	HMODULE hKernel32 = GetModuleHandle(_T("Kernel32.dll"));
	g_fpOldExitProcess = (fpTypeExitProcess)GetProcAddress(hKernel32, "ExitProcess");
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((PVOID*)&g_fpOldExitProcess, MyExitProcess);
	DetourTransactionCommit();
}


///////////////////////////////////对窗体相关的函数做hook//////////////////////////////////////////////////////////////////////////
typedef ATOM(WINAPI *fpTypeRegisterClassExA)(WNDCLASSEXA *lpWndCls);
typedef ATOM(WINAPI *fpTypeRegisterClassA)(WNDCLASSA *lpWndClass);

typedef ATOM(WINAPI *fpTypeRegisterClassExW)(WNDCLASSEXW *lpWndCls);
typedef ATOM(WINAPI *fpTypeRegisterClassW)(WNDCLASSW *lpWndClass);

typedef HWND(WINAPI *fpTypeCreateWindowExW)(
	__in DWORD dwExStyle,
	__in_opt LPCWSTR lpClassName,
	__in_opt LPCWSTR lpWindowName,
	__in DWORD dwStyle,
	__in int X,
	__in int Y,
	__in int nWidth,
	__in int nHeight,
	__in_opt HWND hWndParent,
	__in_opt HMENU hMenu,
	__in_opt HINSTANCE hInstance,
	__in_opt LPVOID lpParam);

typedef HWND(WINAPI *fpTypeCreateWindowExA)(
	__in DWORD dwExStyle,
	__in_opt LPCSTR lpClassName,
	__in_opt LPCSTR lpWindowName,
	__in DWORD dwStyle,
	__in int X,
	__in int Y,
	__in int nWidth,
	__in int nHeight,
	__in_opt HWND hWndParent,
	__in_opt HMENU hMenu,
	__in_opt HINSTANCE hInstance,
	__in_opt LPVOID lpParam);

typedef BOOL(WINAPI *fpTypeSetWindowTextW)(
	_In_      HWND hWnd,
	_In_opt_ LPCWSTR lpString
	);

typedef BOOL(WINAPI *fpTypeSetWindowTextA)(
	_In_ HWND hWnd,
	_In_opt_ LPCSTR lpString
	);




fpTypeRegisterClassExA g_fpRegisterClassExA = NULL;
fpTypeRegisterClassA g_fpRegisterClassA = NULL;

fpTypeRegisterClassExW g_fpRegisterClassExW = NULL;
fpTypeRegisterClassW g_fpRegisterClassW = NULL;

fpTypeCreateWindowExW g_fpCreateWindowExW = NULL;
fpTypeCreateWindowExA g_fpCreateWindowExA = NULL;
fpTypeSetWindowTextW g_fpSetWindowsTextW = NULL;
fpTypeSetWindowTextA g_fpSetWindowsTextA = NULL;

ATOM
WINAPI
MyRegisterClassExA(
WNDCLASSEXA *lpWndCls)
{
	if (lpWndCls->lpszClassName)
	{
		CHAR szNewClassName[MAX_PATH];
		DWORD dwOld;
		OutputDebugStringA(lpWndCls->lpszClassName);
		VirtualProtect((LPVOID)lpWndCls->lpszClassName, strlen(lpWndCls->lpszClassName) + 1, PAGE_EXECUTE_READWRITE, &dwOld);
		wsprintfA(szNewClassName, "%d_%d", GetTickCount(), GetCurrentProcessId());
		RtlCopyMemory((PVOID)lpWndCls->lpszClassName, (PVOID)szNewClassName, strlen(lpWndCls->lpszClassName));
	}
	return g_fpRegisterClassExA(lpWndCls);
}
ATOM
WINAPI
MyRegisterClassA(
WNDCLASSA *lpWndClass)
{
	if (lpWndClass->lpszClassName)
	{
		CHAR szNewClassName[MAX_PATH];
		DWORD dwOld;
		OutputDebugStringA(lpWndClass->lpszClassName);
		VirtualProtect((LPVOID)lpWndClass->lpszClassName, strlen(lpWndClass->lpszClassName) + 1, PAGE_EXECUTE_READWRITE, &dwOld);
		wsprintfA(szNewClassName, "%d_%d", GetTickCount(), GetCurrentProcessId());
		RtlCopyMemory((PVOID)lpWndClass->lpszClassName, (PVOID)szNewClassName, strlen(lpWndClass->lpszClassName));
	}
	return g_fpRegisterClassA(lpWndClass);
}
ATOM
WINAPI
MyRegisterClassExW(
WNDCLASSEXW *lpWndCls)
{
	if (lpWndCls->lpszClassName)
	{
		WCHAR szNewClassName[MAX_PATH];
		DWORD dwOld;
		OutputDebugStringW(lpWndCls->lpszClassName);
		VirtualProtect((LPVOID)lpWndCls->lpszClassName, wcslen(lpWndCls->lpszClassName) + 1, PAGE_EXECUTE_READWRITE, &dwOld);
		wsprintfW(szNewClassName, L"%d_%d", GetTickCount(), GetCurrentProcessId());
		RtlCopyMemory((PVOID)lpWndCls->lpszClassName, (PVOID)szNewClassName, wcslen(lpWndCls->lpszClassName) * 2);
	}
	return g_fpRegisterClassExW(lpWndCls);
}
ATOM
WINAPI
MyRegisterClassW(
WNDCLASSW *lpWndClass)
{
	if (lpWndClass->lpszClassName)
	{
		WCHAR szNewClassName[MAX_PATH];
		DWORD dwOld;
		OutputDebugStringW(lpWndClass->lpszClassName);
		VirtualProtect((LPVOID)lpWndClass->lpszClassName, wcslen(lpWndClass->lpszClassName) + 1, PAGE_EXECUTE_READWRITE, &dwOld);
		wsprintfW(szNewClassName, L"%d_%d", GetTickCount(), GetCurrentProcessId());
		RtlCopyMemory((PVOID)lpWndClass->lpszClassName, (PVOID)szNewClassName, wcslen(lpWndClass->lpszClassName) * 2);
	}
	return g_fpRegisterClassW(lpWndClass);
}

HWND
WINAPI
MyCreateWindowExW(
__in DWORD dwExStyle,
__in_opt LPCWSTR lpClassName,
__in_opt LPCWSTR lpWindowName,
__in DWORD dwStyle,
__in int X,
__in int Y,
__in int nWidth,
__in int nHeight,
__in_opt HWND hWndParent,
__in_opt HMENU hMenu,
__in_opt HINSTANCE hInstance,
__in_opt LPVOID lpParam)
{
	if (lpWindowName)
	{
		WCHAR szNewWndName[MAX_PATH];
		wsprintfW(szNewWndName, L"%d_%ws", GetCurrentProcessId(), lpWindowName);
		lpWindowName = szNewWndName;
	}
	return  g_fpCreateWindowExW(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

HWND
WINAPI
MyCreateWindowExA(
__in DWORD dwExStyle,
__in_opt LPCSTR lpClassName,
__in_opt LPCSTR lpWindowName,
__in DWORD dwStyle,
__in int X,
__in int Y,
__in int nWidth,
__in int nHeight,
__in_opt HWND hWndParent,
__in_opt HMENU hMenu,
__in_opt HINSTANCE hInstance,
__in_opt LPVOID lpParam)
{
	if (lpWindowName)
	{
		CHAR szNewWndName[MAX_PATH];
		wsprintfA(szNewWndName, "%d_%s", GetCurrentProcessId(), lpWindowName);
		lpWindowName = szNewWndName;
	}
	return  g_fpCreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}


BOOL WINAPI MySetWindowTextW(
	_In_      HWND hWnd,
	_In_opt_  LPCTSTR lpString
	)
{
	if (lpString)
	{
		WCHAR buff[MAX_PATH];
		wsprintf(buff, L"%d_%s", GetCurrentProcessId(), lpString);
	}
	return g_fpSetWindowsTextW(hWnd, lpString);
}

BOOL WINAPI MySetWindowTextA(
	_In_      HWND hWnd,
	_In_opt_ LPCSTR lpString
	)
{
	if (lpString)
	{
		char buff[MAX_PATH];
		wsprintfA(buff, "%d_%s", GetCurrentProcessId(), lpString);
	}
	return g_fpSetWindowsTextA(hWnd, lpString);
}



VOID OnHookWnd()
{
	HMODULE hUsr32 = GetModuleHandle(_T("user32.dll"));
	PVOID ProcAddress = NULL;
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	g_fpRegisterClassExA = (fpTypeRegisterClassExA)GetProcAddress(hUsr32, "RegisterClassExA");
	g_fpRegisterClassA = (fpTypeRegisterClassA)GetProcAddress(hUsr32, "RegisterClassA");
	g_fpRegisterClassExW = (fpTypeRegisterClassExW)GetProcAddress(hUsr32, "RegisterClassExW");
	g_fpRegisterClassW = (fpTypeRegisterClassW)GetProcAddress(hUsr32, "RegisterClassW");
	g_fpCreateWindowExW = (fpTypeCreateWindowExW)GetProcAddress(hUsr32, "CreateWindowExW");
	g_fpCreateWindowExA = (fpTypeCreateWindowExA)GetProcAddress(hUsr32, "CreateWindowExA");
	g_fpSetWindowsTextW = (fpTypeSetWindowTextW)GetProcAddress(hUsr32, "SetWindowTextW");
	g_fpSetWindowsTextA = (fpTypeSetWindowTextA)GetProcAddress(hUsr32, "SetWindowTextA");

	DetourAttach((PVOID*)&g_fpRegisterClassExA, MyRegisterClassExA);
	DetourAttach((PVOID*)&g_fpRegisterClassA, MyRegisterClassA);
	DetourAttach((PVOID*)&g_fpRegisterClassExW, MyRegisterClassExW);
	DetourAttach((PVOID*)&g_fpRegisterClassW, MyRegisterClassW);
	DetourAttach((PVOID*)&g_fpCreateWindowExW, MyCreateWindowExW);
	DetourAttach((PVOID*)&g_fpCreateWindowExA, MyCreateWindowExA);
	//DetourAttach((PVOID*)&g_fpSetWindowsTextW, MySetWindowTextW);
	//DetourAttach((PVOID*)&g_fpSetWindowsTextA, MySetWindowTextA);
	DetourTransactionCommit();

}






///////////////////////

typedef BOOL (WINAPI *fpTypeIsWindow)(_In_opt_ HWND hWnd);
fpTypeIsWindow fpIsWindows = NULL;

BOOL WINAPI MyIsWindow(HWND hWnd)
{
	return fpIsWindows(hWnd);
}

VOID OnIsWindow()
{
	HMODULE hUsr32 = GetModuleHandle(_T("user32.dll"));
	fpIsWindows = (fpTypeIsWindow)GetProcAddress(hUsr32, "IsWindow");
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DetourAttach((PVOID*)&fpIsWindows, MyIsWindow);


	DetourTransactionCommit();

}


