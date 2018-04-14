#include "FileVersionInfo.h"
#include <tchar.h>
#include <WinVer.h>
#include <wincrypt.h>
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "crypt32.lib")
#pragma warning(disable: 4996)


CFileVersionInfo::CFileVersionInfo()
{
}
//
CFileVersionInfo::CFileVersionInfo(const wchar_t* szFileName)
{
	HRESULT hr = S_OK;

	hr = this->Load(szFileName);
	if (FAILED(hr))
	{
		NULL;
	}
}
//
CFileVersionInfo::CFileVersionInfo(const wchar_t* szFileName, CLangAndCodePage LangAndCodePage)
{
	HRESULT hr = S_OK;

	hr = this->Load(szFileName, LangAndCodePage);
	if (FAILED(hr))
	{
		NULL;
	}
}
//
CFileVersionInfo::~CFileVersionInfo()
{
}
std::wstring CFileVersionInfo::GetComments()
{
	return m_strComments;
}
std::wstring CFileVersionInfo::GetCompanyName()
{
	return m_strCompanyName;
}
std::wstring CFileVersionInfo::GetFileDescription()
{
	return m_strFileDescription;
}
std::wstring CFileVersionInfo::GetFileVersion()
{
	if (m_strFileVersion.find(L',') != m_strFileVersion.npos)
	{
		int ver[4];
		GetFileVersionArray(ver);
		wchar_t buf[256];
		swprintf(buf, 256, L"%d.%d.%d.%d", ver[0], ver[1], ver[2], ver[3]);
		return std::wstring(buf);
	}
	return m_strFileVersion;
}
std::wstring CFileVersionInfo::GetInternalName()
{
	return m_strInternalName;
}
std::wstring CFileVersionInfo::GetLegalCopyright()
{
	return m_strLegalCopyright;
}
std::wstring CFileVersionInfo::GetLegalTrademarks()
{
	return m_strLegalTrademarks;
}
std::wstring CFileVersionInfo::GetOriginalTrademarks()
{
	return m_strOriginalFilename;
}
std::wstring CFileVersionInfo::GetPrivateBuild()
{
	return m_strPrivateBuild;
}
std::wstring CFileVersionInfo::GetProductName()
{
	return m_strProductName;
}
std::wstring CFileVersionInfo::GetProductVersion()
{
	return m_strProductVersion;
}
std::wstring CFileVersionInfo::GetSpecialBuild()
{
	return m_strSpecialBuild;
}
UINT CFileVersionInfo::GetBuildNumber()
{
	//找不到资源文件，或者其他问题会返回0
	UINT nBuildNum = 0;
	std::wstring s = m_strFileVersion;
	size_t nPos = s.rfind(L'.');
	if (nPos > 1)
	{
		s = s.substr(nPos + 1);
		nBuildNum = _wtoi(s.c_str());
	}
	return nBuildNum;
}
void CFileVersionInfo::GetFileVersionArray(int v[4])
{
	const wchar_t *p = m_strFileVersion.c_str();
	if (m_strFileVersion.find(L',') != m_strFileVersion.npos)
		swscanf(p, L"%d,%d,%d,%d", &v[0], &v[1], &v[2], &v[3]);
	else
		swscanf(p, L"%d.%d.%d.%d", &v[0], &v[1], &v[2], &v[3]);
}
//
HRESULT CFileVersionInfo::Load(const wchar_t* szFileName, CLangAndCodePage LangAndCodePage)
{
	wchar_t lpPath[MAX_PATH] = { 0 };

	if (szFileName == NULL)
	{
		::GetModuleFileNameW(NULL, lpPath, MAX_PATH);
		szFileName = lpPath;
	}

	HRESULT hr = S_OK;

	LPVOID lpBlock = _AllocFileVersionInfoBlock(szFileName);
	if (lpBlock == NULL)
	{
		return E_OUTOFMEMORY;
	}

	hr = _GetStringFileInfo(lpBlock, LangAndCodePage, _T("Comments"), m_strComments);
	hr = _GetStringFileInfo(lpBlock, LangAndCodePage, _T("CompanyName"), m_strCompanyName);
	hr = _GetStringFileInfo(lpBlock, LangAndCodePage, _T("FileDescription"), m_strFileDescription);
	hr = _GetStringFileInfo(lpBlock, LangAndCodePage, _T("FileVersion"), m_strFileVersion);
	hr = _GetStringFileInfo(lpBlock, LangAndCodePage, _T("InternalName"), m_strInternalName);
	hr = _GetStringFileInfo(lpBlock, LangAndCodePage, _T("LegalCopyright"), m_strLegalCopyright);
	hr = _GetStringFileInfo(lpBlock, LangAndCodePage, _T("LegalTrademarks"), m_strLegalTrademarks);
	hr = _GetStringFileInfo(lpBlock, LangAndCodePage, _T("OriginalFilename"), m_strOriginalFilename);
	hr = _GetStringFileInfo(lpBlock, LangAndCodePage, _T("PrivateBuild"), m_strPrivateBuild);
	hr = _GetStringFileInfo(lpBlock, LangAndCodePage, _T("ProductName"), m_strProductName);
	hr = _GetStringFileInfo(lpBlock, LangAndCodePage, _T("ProductVersion"), m_strProductVersion);
	hr = _GetStringFileInfo(lpBlock, LangAndCodePage, _T("SpecialBuild"), m_strSpecialBuild);

	_FreeFileVersionInfoBlock(lpBlock);

	return S_OK;
}
//
HRESULT CFileVersionInfo::Load(const wchar_t* szFileName)
{
	wchar_t lpPath[MAX_PATH] = { 0 };

	if (szFileName == NULL)
	{
		::GetModuleFileNameW(NULL, lpPath, MAX_PATH);
		szFileName = lpPath;
	}

	HRESULT hr = S_OK;

	std::vector<CLangAndCodePage> LangAndCodePages;
	hr = EnumLangAndCodePages(szFileName, LangAndCodePages);
	if (FAILED(hr))
	{
		return hr;
	}

	return this->Load(szFileName, LangAndCodePages[0]);
}
//
HRESULT CFileVersionInfo::EnumLangAndCodePages(const wchar_t* szFileName, std::vector<CLangAndCodePage>& LangAndCodePages)
{
	if (szFileName == NULL)
	{
		return E_FAIL;
	}

	HRESULT hr = S_OK;

	LPVOID lpBlock = _AllocFileVersionInfoBlock(szFileName);
	if (lpBlock == NULL)
	{
		return E_OUTOFMEMORY;
	}

	hr = _EnumLangAndCodePages(lpBlock, LangAndCodePages);

	_FreeFileVersionInfoBlock(lpBlock);

	return hr;
}
//
std::wstring CFileVersionInfo::GetCertificateName(std::wstring filePath)
{
	std::wstring cfeName;
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	PCMSG_SIGNER_INFO pSignerInfo = NULL;
	DWORD dwSignerInfo;
	CERT_INFO CertInfo;
	wchar_t szName[1024] = { 0 };

	// Get message handle and store handle from the signed file.
	BOOL fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(), CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL, &hStore, &hMsg, NULL);
	if (!fResult)
	{
		goto __GetCertificateNameEnd;
	}
	// Get signer information size.
	fResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo);
	if (!fResult)
	{
		goto __GetCertificateNameEnd;
	}
	// Allocate memory for signer information.
	pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
	if (!pSignerInfo)
	{
		goto __GetCertificateNameEnd;
	}
	// Get Signer Information.
	fResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, (PVOID)pSignerInfo, &dwSignerInfo);
	if (!fResult)
	{
		goto __GetCertificateNameEnd;
	}

	CertInfo.Issuer = pSignerInfo->Issuer;
	CertInfo.SerialNumber = pSignerInfo->SerialNumber;
	pCertContext = CertFindCertificateInStore(hStore, (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING), 0,
		CERT_FIND_SUBJECT_CERT, (PVOID)&CertInfo, NULL);
	if (!pCertContext)
	{
		goto __GetCertificateNameEnd;
	}

	if (dwSignerInfo = CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, NULL, NULL, NULL, 0))
	{
		if (CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, NULL, NULL, szName, dwSignerInfo))
		{
			cfeName = szName;
		}
	}

__GetCertificateNameEnd:
	if (pSignerInfo != NULL) LocalFree(pSignerInfo);
	if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
	if (hStore != NULL) CertCloseStore(hStore, 0);
	if (hMsg != NULL) CryptMsgClose(hMsg);

	return cfeName;
}

// 文件版本信息块
LPVOID CFileVersionInfo::_AllocFileVersionInfoBlock(const wchar_t* szFileName)
{
	if (szFileName == NULL)
	{
		return NULL;
	}

	DWORD dwHandle = 0;
	DWORD dwBlockSize = ::GetFileVersionInfoSize(szFileName, &dwHandle);
	if (dwBlockSize <= 0)
	{
		return NULL;
	}

	LPVOID lpBlock = new char[dwBlockSize];
	if (lpBlock == NULL)
	{
		return NULL;
	}

	BOOL br = ::GetFileVersionInfoW(szFileName, dwHandle, dwBlockSize, lpBlock);
	if (br == FALSE)
	{
		delete[] lpBlock;
		return NULL;
	}

	return lpBlock;
}
void CFileVersionInfo::_FreeFileVersionInfoBlock(LPVOID lpBlock)
{
	delete[] lpBlock;
}

HRESULT CFileVersionInfo::_EnumLangAndCodePages(const LPVOID lpBlock, std::vector<CLangAndCodePage>& LangAndCodePages)
{
	if (lpBlock == NULL)
	{
		return E_FAIL;
	}

	// 清除
	LangAndCodePages.clear();

	wchar_t strSubBlock[] = L"\\VarFileInfo\\Translation";
	LPVOID lpBuffer = NULL;
	UINT uLen = 0;

	BOOL br = ::VerQueryValue(lpBlock, strSubBlock, (LPVOID*)&lpBuffer, &uLen);
	if (br == 0)
	{
		return E_FAIL;
	}

	for (int i = 0; i < (int)(uLen / sizeof(struct LANGANDCODEPAGE)); i++)
	{
		LANGANDCODEPAGE* pLangAndCodePage = (LANGANDCODEPAGE*)lpBuffer;

		LangAndCodePages.push_back(pLangAndCodePage[i]);
	}

	return S_OK;
}
// szName = "Comments" or "CompanyName" or "FileDescription" or "FileVersion" or
//          "InternalName" or "LegalCopyright" or "LegalTrademarks" or "OriginalFilename" or
//          "PrivateBuild" or "ProductName" or "ProductVersion" or "SpecialBuild"
HRESULT CFileVersionInfo::_GetStringFileInfo(const LPVOID lpBlock, CLangAndCodePage LangAndCodePage, const wchar_t* szName, std::wstring& strValue)
{
	if (lpBlock == NULL)
	{
		return E_FAIL;
	}

	// 清除
	strValue = _T("");

	wchar_t strSubBlock[256];
	swprintf(strSubBlock, 256, L"\\StringFileInfo\\%04x%04x\\%s", LangAndCodePage.wLanguage, LangAndCodePage.wCodePage, szName);
	LPVOID lpBuffer = NULL;
	UINT uLen = 0;

	BOOL br = ::VerQueryValueW(lpBlock, strSubBlock, &lpBuffer, &uLen);
	if (br == 0)
	{
		return E_FAIL;
	}

	strValue = (const wchar_t*)lpBuffer;

	return S_OK;
}
