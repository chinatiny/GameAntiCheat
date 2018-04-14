#pragma once

#include "detours/detours.h"

#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <shlwapi.h>  
#include "Dbg.h"
#include "UnDocoumentApi.h"
#include "CheatMsg.h"

#pragma comment(lib,"detours/lib.X86/detours.lib")
#pragma comment(lib,"shlwapi.lib")  
#pragma  comment(lib, "Advapi32.lib")
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"psapi.lib")
#pragma comment(lib, "user32.lib")

#define DRIVER_FILE_NAME _T("AntiCheatDriver.sys")

#define  WCHAR_TO_CHAR(lpW_Char, lpChar) \
	WideCharToMultiByte(CP_ACP, NULL, lpW_Char, -1, lpChar, _countof(lpChar), NULL, FALSE);

// ¶à×Ö·û×ª»»Îª¿í×Ö·û(ASCII --> Unicode)
#define  CHAR_TO_WCHAR(lpChar, lpW_Char) \
	MultiByteToWideChar(CP_ACP, NULL, lpChar, -1, lpW_Char, _countof(lpW_Char));



