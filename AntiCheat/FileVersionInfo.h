#ifndef __BASE_FILE_VERSION_H__
#define __BASE_FILE_VERSION_H__
#include <wtypes.h>
#include <vector>
// 语言与代码页
struct LANGANDCODEPAGE
{
	WORD wLanguage;
	WORD wCodePage;
};

//class CLangAndCodePage 
class CLangAndCodePage : public LANGANDCODEPAGE
{
public:
	CLangAndCodePage()
	{
		wLanguage = 0;
		wCodePage = 0;
	}
	CLangAndCodePage(const LANGANDCODEPAGE& wLangAndCodePageSrc)
	{
		wLanguage = wLangAndCodePageSrc.wLanguage;
		wCodePage = wLangAndCodePageSrc.wCodePage;
	}
	CLangAndCodePage(WORD wLanguageSrc, WORD wCodePageSrc)
	{
		wLanguage = wLanguageSrc;
		wCodePage = wCodePageSrc;
	}
};

//class CFileVersionInfo 
class CFileVersionInfo
{
public:
	CFileVersionInfo();
	CFileVersionInfo(const wchar_t* szFileName);
	CFileVersionInfo(const wchar_t* szFileName, CLangAndCodePage LangAndCodePage);
	virtual ~CFileVersionInfo();

	std::wstring GetComments();
	std::wstring GetCompanyName();
	std::wstring GetFileDescription();
	std::wstring GetFileVersion();
	std::wstring GetInternalName();
	std::wstring GetLegalCopyright();
	std::wstring GetLegalTrademarks();
	std::wstring GetOriginalTrademarks();
	std::wstring GetPrivateBuild();
	std::wstring GetProductName();
	std::wstring GetProductVersion();
	std::wstring GetSpecialBuild();

	HRESULT Load(const wchar_t* szFileName);
	HRESULT Load(const wchar_t* szFileName, CLangAndCodePage LangAndCodePage);

protected:
	UINT GetBuildNumber();
	void GetFileVersionArray(int v[4]);
	//
	static HRESULT EnumLangAndCodePages(const wchar_t* szFileName, std::vector<CLangAndCodePage>& LangAndCodePages);
	static std::wstring GetCertificateName(std::wstring filePath);

	// 文件版本信息块
	static LPVOID _AllocFileVersionInfoBlock(const wchar_t* szFileName);
	static void _FreeFileVersionInfoBlock(LPVOID lpBlock);

	static HRESULT _EnumLangAndCodePages(const LPVOID lpBlock, std::vector<CLangAndCodePage>& LangAndCodePages);

	// szName = "Comments" or "CompanyName" or "FileDescription" or "FileVersion" or
	//          "InternalName" or "LegalCopyright" or "LegalTrademarks" or "OriginalFilename" or
	//          "PrivateBuild" or "ProductName" or "ProductVersion" or "SpecialBuild"
	static HRESULT _GetStringFileInfo(const LPVOID lpBlock,
		CLangAndCodePage LangAndCodePage,
		const wchar_t* szName,
		std::wstring& strValue);

protected:
	std::wstring m_strFileName;

	std::wstring m_strComments;
	std::wstring m_strCompanyName;
	std::wstring m_strFileDescription;
	std::wstring m_strFileVersion;
	std::wstring m_strInternalName;
	std::wstring m_strLegalCopyright;
	std::wstring m_strLegalTrademarks;
	std::wstring m_strOriginalFilename;
	std::wstring m_strPrivateBuild;
	std::wstring m_strProductName;
	std::wstring m_strProductVersion;
	std::wstring m_strSpecialBuild;
};

#endif//__BASE_FILE_VERSION_H__