#include "CheckLoop.h"
#include "AntiHideLib.h"
#include "AntiApc.h"
#include <winsock2.h>
#include <tchar.h>
#include "UnDocoumentApi.h"
#include <shlwapi.h>  
#include <process.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include "Dbg.h"
#include "FileVersionInfo.h"
#include "AntiPE.h"
#include "AntiCreateProcess.h"
// Link with the Wintrust.lib file.
#pragma comment (lib, "wintrust")

#ifdef _UNICODE
#define  String std::wstring
#else
#define  String std::string
#endif

//进程中的模块的md5信息
typedef struct
{
	String strDllPath;
	String strMd5;
	String strVersion;
}ModInfo;


//模块信息
static std::vector<ModInfo> s_vecMd5Info;

#pragma comment(lib,"shlwapi.lib")  

#define  WCHAR_TO_CHAR(lpW_Char, lpChar) \
	WideCharToMultiByte(CP_ACP, NULL, lpW_Char, -1, lpChar, _countof(lpChar), NULL, FALSE);

// 多字符转换为宽字符(ASCII --> Unicode)
#define  CHAR_TO_WCHAR(lpChar, lpW_Char) \
	MultiByteToWideChar(CP_ACP, NULL, lpChar, -1, lpW_Char, _countof(lpW_Char));




typedef struct tagPACKED_CATALOG_ITEM
{
	char spi_path[MAX_PATH];
	WSAPROTOCOL_INFO protocol_info;
} PACKED_CATALOG_ITEM, *PPACKED_CATALOG_ITEM;


BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
	LONG lStatus;
	DWORD dwLastError;

	// Initialize the WINTRUST_FILE_INFO structure.

	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = pwszSourceFile;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	BOOL bRet = FALSE;
	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;

	// Initialize the WinVerifyTrust input data structure.

	// Default all fields to 0.
	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.cbStruct = sizeof(WinTrustData);

	// Use default code signing EKU.
	WinTrustData.pPolicyCallbackData = NULL;

	// No data to pass to SIP.
	WinTrustData.pSIPClientData = NULL;

	// Disable WVT UI.
	WinTrustData.dwUIChoice = WTD_UI_NONE;

	// No revocation checking.
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

	// Verify an embedded signature on a file.
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

	// Verify action.
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	// Verification sets this value.
	WinTrustData.hWVTStateData = NULL;

	// Not used.
	WinTrustData.pwszURLReference = NULL;

	// This is not applicable if there is no UI because it changes 
	// the UI to accommodate running applications instead of 
	// installing applications.
	WinTrustData.dwUIContext = 0;

	// Set pFile.
	WinTrustData.pFile = &FileData;

	// WinVerifyTrust verifies signatures as specified by the GUID 
	// and Wintrust_Data.
	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	switch (lStatus)
	{
	case ERROR_SUCCESS:
		bRet = TRUE;
		break;

	case TRUST_E_NOSIGNATURE:
		dwLastError = GetLastError();
		if (TRUST_E_NOSIGNATURE == dwLastError ||
			TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
			TRUST_E_PROVIDER_UNKNOWN == dwLastError)
		{
			//nothing
		}
		else
		{
			bRet = TRUE;
		}

		break;

	case TRUST_E_EXPLICIT_DISTRUST:
		break;

	case TRUST_E_SUBJECT_NOT_TRUSTED:
		break;

	case CRYPT_E_SECURITY_SETTINGS:
		break;

	default:
		break;
	}
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);
	return bRet;
}

//LdrpHashTable
LIST_ENTRY *GetHashTableAddress()
{
	HANDLE hModule = GetModuleHandle(TEXT("ntdll.dll"));
	BYTE *p = NULL;
	LIST_ENTRY *retval = NULL;
	BYTE pSign[] = { 0x83, 0xE0, 0x1F, 0x8D, 0x04, 0xC5 };
	DWORD SignLen = 6;
	_tprintf(TEXT("ntdll base:%08x\r\n"), hModule);
	__try
	{
		DWORD dwAddress = (DWORD)GetProcAddress((HMODULE)hModule, "LdrLoadDll");
		for (DWORD i = 0; i < 0x100000; i++)
		{
			//
			if (memcmp((BYTE *)(dwAddress + i), pSign, SignLen) == 0)
			{
				p = (BYTE *)((DWORD)dwAddress + i);
				_tprintf(TEXT("address:%08x\r\n"), p);
				p += 6;
				retval = (LIST_ENTRY *)(*(DWORD *)p);
				break;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		//
	}
	return retval;
}

VOID CheckSelfMoByHashTable(HANDLE hProcess, LIST_ENTRY *LdrpHashTable)
{
	LIST_ENTRY *LdrpHashTableTemp = NULL, *pListEntry, *pListHead;
	UNICODE_STRING *pDllFullPath;
	void *pTemp;
	DWORD size;
	LDR_DATA_TABLE_ENTRYEX LdrDataEntry;

	size = sizeof(LIST_ENTRY)* 32;
	pTemp = malloc(size);

	//读Hash表
	if (ReadProcessMemory(hProcess, LdrpHashTable, pTemp, size, &size))
	{
		LdrpHashTableTemp = (LIST_ENTRY *)pTemp;

		for (DWORD i = 0; i < 32; i++)
		{
			pListEntry = LdrpHashTableTemp + i;
			pListEntry = pListEntry->Flink;
			pListHead = LdrpHashTable + i;

			int nCount = 0;

			while (pListEntry != pListHead)
			{
				++nCount;
				if (nCount > 100) break;
				size = sizeof(LIST_ENTRY);
				pTemp = malloc(size);
				if (ReadProcessMemory(hProcess, (BYTE *)pListEntry - 0x3c, &LdrDataEntry, sizeof(LdrDataEntry), &size))
				{
					//读模块路径保存在pTemp中
					pDllFullPath = &LdrDataEntry.FullDllName;
					pTemp = malloc(pDllFullPath->MaximumLength);
					memset(pTemp, 0, pDllFullPath->MaximumLength);
					if (ReadProcessMemory(hProcess, pDllFullPath->Buffer, pTemp, pDllFullPath->Length, &size))
					{
						TCHAR szFileName[MAX_PATH] = { 0 };
						GetModuleFileName(NULL, szFileName, _countof(szFileName));
						if (!VerifyEmbeddedSignature((LPCWSTR)pTemp) && _tcscmp(szFileName, (LPCWSTR)pTemp))
						{
							CFileVersionInfo fileV((LPCWSTR)pTemp);
							if (fileV.GetCompanyName() == L"Microsoft Corporation" ||
								fileV.GetCompanyName() == L"NVIDIA Corporation") continue;
							//
							TCHAR szFullPath[MAX_PATH] = { 0 };
							_tcscpy_s(szFullPath, _countof(szFullPath), (TCHAR*)pTemp);
							PathStripPath((LPTSTR)pTemp);
							if (!_tcscmp((LPCWSTR)pTemp, L"AntiCheat.dll") ||
								!_tcscmp((LPCWSTR)pTemp, L"LoliCore32.dll")
								) continue;


							PrintDbgInfo(_T("公司%s || dll：%s, 需要上传到服务器"), fileV.GetCompanyName().c_str(), szFullPath);
						}
					}
					free(pTemp);
				}
				pListEntry = LdrDataEntry.HashLinks.Flink;

			}
		}
	}
	if (!LdrpHashTableTemp)
		free(LdrpHashTableTemp);

	return;
}

VOID CheckSelfMod()
{
	LIST_ENTRY *LdrpHashTable;
	LdrpHashTable = GetHashTableAddress();
	if (LdrpHashTable)
	{
		CheckSelfMoByHashTable(GetCurrentProcess(), LdrpHashTable);
	}
	return;
}


//获取分层服务在什么目录下
void GetCurrentProtocolCatalogPath(TCHAR *pszCatelogPath, int nccSize)
{
	DWORD type = REG_SZ;
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD chData = sizeof(buffer);

	//
	HKEY hValueKey = NULL;
	RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		_T("System\\CurrentControlSet\\Services\\Winsock2\\Parameters"),
		0,
		KEY_QUERY_VALUE,
		&hValueKey);
	if (NULL == hValueKey) return;


	RegQueryValueEx(
		hValueKey,
		_T("Current_Protocol_Catalog"),
		0,
		&type,
		(LPBYTE)buffer,
		&chData);
	_stprintf_s(pszCatelogPath, nccSize, _T("%s\\%s\\Catalog_Entries"), _T("System\\CurrentControlSet\\Services\\Winsock2\\Parameters"), buffer);
	//
	RegCloseKey(hValueKey);
}

//枚举LSP
void EnumLsp(TCHAR *szEntryPath)
{
	HKEY hResult = NULL;  //用来接收打开键的句柄
	RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		szEntryPath,
		0,
		KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
		&hResult
		);
	if (NULL == hResult) return;


	DWORD dwIndex = 0;
	while (true)
	{
		DWORD dwKeyLen = MAX_PATH;
		TCHAR szNewKeyName[MAX_PATH];

		LONG lReturn = RegEnumKeyEx(
			hResult,
			dwIndex,
			szNewKeyName,
			&dwKeyLen,
			0,
			NULL,
			NULL,
			NULL
			);
		if (ERROR_SUCCESS != lReturn) break;

		//获取具体的Lsp项
		TCHAR szMidReg[MAX_PATH] = { 0 };
		_stprintf_s(szMidReg, _countof(szMidReg), _T("%s%s%s"), szEntryPath, _T("\\"), szNewKeyName);

		//打开具体项
		DWORD dwRegType;
		HKEY hValueKey = NULL;
		RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			szMidReg,
			0,
			KEY_QUERY_VALUE,
			&hValueKey);

		if (NULL != hValueKey)
		{
			TCHAR szRegValue[MAX_PATH];
			ZeroMemory(szRegValue, sizeof(szRegValue));
			DWORD dwRealLen = _countof(szRegValue);

			//获取服务名
			RegQueryValueEx(
				hValueKey,
				_T("ProtocolName"),
				0,
				&dwRegType,
				(LPBYTE)szRegValue,
				&dwRealLen);
			_tprintf(_T("服务名字:%s\n"), szRegValue);

			//获取dll的全路径名
			PACKED_CATALOG_ITEM catelogItem;
			ZeroMemory(&catelogItem, sizeof(catelogItem));
			dwRealLen = sizeof(catelogItem);
			RegQueryValueEx(
				hValueKey,
				_T("PackedCatalogItem"),
				0,
				&dwRegType,
				(LPBYTE)&catelogItem,
				&dwRealLen);
			//
			TCHAR szWinDllPath[MAX_PATH] = { 0 };
#ifdef _UNICODE
			CHAR_TO_WCHAR(catelogItem.spi_path, szWinDllPath);
#else
			strcpy_s(szWinDllPath, _countof(szWinDllPath), catelogItem.spi_path);
#endif
			TCHAR szAbDllPath[MAX_PATH] = { 0 };
			ExpandEnvironmentStrings(szWinDllPath, szAbDllPath, _countof(szAbDllPath));
			if (!VerifyEmbeddedSignature(szAbDllPath))
			{
				CFileVersionInfo fileV((LPCWSTR)szAbDllPath);
				if (fileV.GetCompanyName() != L"Microsoft Corporation")
				{
					PrintDbgInfo(_T("未签名的lsp:%s"), szAbDllPath);
					ExitProcess(4);
				}
			}
			RegCloseKey(hValueKey);
		}
		dwIndex++;
	}
	if (NULL != hResult) 	RegCloseKey(hResult);
}


void CheckLsp()
{
	TCHAR szCateLogPath[MAX_PATH] = { 0 };
	GetCurrentProtocolCatalogPath(szCateLogPath, _countof(szCateLogPath));
	EnumLsp(szCateLogPath);
}

unsigned int __stdcall CheckLoop(void* pArg)
{

	while (true)
	{
		if (IsFondApcInject())
		{
			ExitProcess(2);
		}
		//检测自身模块,并且上传
		CheckSelfMod();
		//检测可疑的lsp
		CheckLsp();
		//检测dll劫持
		CheckModPEInfo();
		//上传劫持模块
		IsFondHackDll();
		//父进程不对
		if (IsSuspendProcess())
		{
			ExitProcess(6);
		}
		Sleep(5000);
	}
	return 1;
}

//对外接口
void CheckLoop()
{
	unsigned int uThreadID = 0;
	_beginthreadex(0, 0, CheckLoop, 0, 0, &uThreadID);
}
