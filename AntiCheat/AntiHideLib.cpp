#include "AntiHideLib.h"
#include "AntiCheat.h"
#include "Dbg.h"
#include "ProcessOperation.h"
#include "PEOperation.h"
#include "UnDocoumentApi.h"

#include "detours/detours.h"
#pragma comment(lib,"detours/lib.X86/detours.lib")

// BegEngine在使用的时候需要定义下
#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
#include "BeaEngine_4.1/Win32/headers/BeaEngine.h"
#pragma comment (lib , "BeaEngine_4.1/Win32/Win32/Lib/BeaEngine.lib")
// 防止编译错误。
#pragma comment(linker, "/NODEFAULTLIB:\"crt.lib\"")



//////////////////////////////类型定义///////////////////////////////////////

typedef NTSTATUS(WINAPI *fpLdrLoadDll)(
	IN PWCHAR PathToFile OPTIONAL,
	IN ULONG Flags OPTIONAL,
	IN PUNICODE_STRING ModuleFileName,
	OUT PHANDLE ModuleHandle);

//////////////////////////////内部函数///////////////////////////////////////
static fpLdrLoadDll s_fpSrcLdrDll = NULL;
static bool s_bHidMode = false;   //是否：加载的动态库是否有隐藏模块的动作



//山寨版本的ldrloaddll
static NTSTATUS WINAPI MyLdrLoadDll(
	IN PWCHAR PathToFile OPTIONAL,
	IN ULONG Flags OPTIONAL,
	IN PUNICODE_STRING ModuleFileName,
	OUT PHANDLE ModuleHandle)
{
	NTSTATUS ntStatus;
	WCHAR szDllName[MAX_PATH];
	ZeroMemory(szDllName, sizeof(szDllName));
	memcpy(szDllName, ModuleFileName->Buffer, ModuleFileName->Length);
	//在加载之前判断下该模块是否被加载过
	HMODULE hPreMod = GetModuleHandleW(szDllName);
	ntStatus = s_fpSrcLdrDll(PathToFile, Flags, ModuleFileName, ModuleHandle);
	DWORD dwLastError = GetLastError();
	//如果没有被加载过，在执行完s_fpSrcLdrDll成功后检测是否做了隐藏自己的操作
	if (STATUS_SUCCESS == ntStatus &&NULL == hPreMod)
	{
		//GetModuleHandleW其实是读取peb的消息,没必要再遍历一遍了
		HMODULE hNowMod = GetModuleHandleW(szDllName);
		if (NULL == hNowMod) s_bHidMode = true;
	}
	//恢复错误码
	SetLastError(dwLastError);
	return ntStatus;
}



//////////////////////////////对外接口///////////////////////////////////////
void MonitorLoadDll()
{
	HMODULE hNtDll = LoadLibrary(_T("ntdll.dll"));
	HMODULE hK32 = LoadLibrary(_T("Kernel32.dll"));
	s_fpSrcLdrDll = (fpLdrLoadDll)GetProcAddress(hNtDll, "LdrLoadDll");
	//
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((PVOID*)&s_fpSrcLdrDll, MyLdrLoadDll);
	DetourTransactionCommit();
}


bool IsFondModHidSelf()
{
	return s_bHidMode;
}
