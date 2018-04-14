#include "SSDT.h"


int  GetSSDTOrderByName(const char* szFuncName)
{
	//返回的序号
	int nOrder = -1;
	
	IO_STATUS_BLOCK ioStatus;
	//设置NTDLL路径
	UNICODE_STRING uniFileName;
	RtlInitUnicodeString(&uniFileName, L"\\SystemRoot\\system32\\ntdll.dll");

	//初始化打开文件的属性
	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, &uniFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	////创建文件
	NTSTATUS Status;
	HANDLE FileHandle;
	Status = IoCreateFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &objectAttributes,
		&ioStatus, 0, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("IoCreateFile failed！status:0x%08x\n", Status);
		return 0;
	}
	//获取文件信息
	FILE_STANDARD_INFORMATION FileInformation;
	Status = ZwQueryInformationFile(FileHandle, &ioStatus, &FileInformation,
		sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("ZwQueryInformationFile failed！status:0x%08x\n", Status);
		ZwClose(FileHandle);
		return 0;
	}
	//判断文件大小是否过大
	if (FileInformation.EndOfFile.HighPart != 0)
	{
		DbgPrint("File Size Too High");
		ZwClose(FileHandle);
		return 0;
	}
	//取文件大小
	ULONG uFileSize = FileInformation.EndOfFile.LowPart;
	//分配内存
	PVOID pBuffer = ExAllocatePoolWithTag(PagedPool, uFileSize, (ULONG)"NTDLL");
	if (pBuffer == NULL)
	{
		DbgPrint("ExAllocatePoolWithTag() == NULL");
		ZwClose(FileHandle);
		return 0;
	}
	//从头开始读取文件
	LARGE_INTEGER byteOffset;
	byteOffset.LowPart = 0;
	byteOffset.HighPart = 0;
	Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &ioStatus, pBuffer, uFileSize, &byteOffset, NULL);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("ZwReadFile failed！status:0x%08x\n", Status);
		ZwClose(FileHandle);
		return 0;
	}
	//取出导出表
	PIMAGE_DOS_HEADER  pDosHeader;
	PIMAGE_NT_HEADERS  pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	ULONG     FileOffset;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	//DLL内存数据转成DOS头结构
	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
	//取出PE头结构
	pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG)pBuffer + pDosHeader->e_lfanew);
	//判断PE头导出表表是否为空
	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		DbgPrint("VirtualAddress == 0");
		return 0;
	}
	//取出导出表偏移
	FileOffset = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	//取出节头结构
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER pOldSectionHeader = pSectionHeader;
	//遍历节结构进行地址运算
	for (WORD Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset &&
			FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	//导出表地址
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG)pBuffer + FileOffset);
	//取出导出表函数地址
	PULONG AddressOfFunctions;
	FileOffset = pExportDirectory->AddressOfFunctions;
	//遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;
	for (WORD Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset &&
			FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	AddressOfFunctions = (PULONG)((ULONG)pBuffer + FileOffset);

	//取出导出表函数名字
	PUSHORT AddressOfNameOrdinals;
	FileOffset = pExportDirectory->AddressOfNameOrdinals;
	//遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;
	for (WORD Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset &&
			FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	AddressOfNameOrdinals = (PUSHORT)((ULONG)pBuffer + FileOffset);
	//取出导出表函数序号
	PULONG AddressOfNames;
	FileOffset = pExportDirectory->AddressOfNames;
	//遍历节结构进行地址运算
	pSectionHeader = pOldSectionHeader;
	for (WORD Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset &&
			FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
		{
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
	}
	AddressOfNames = (PULONG)((ULONG)pBuffer + FileOffset);
	//分析导出表
	ULONG uNameOffset = 0;
	ULONG uOffset = 0;
	LPSTR FunName;
	PVOID pFuncAddr;
	ULONG uServerIndex;
	ULONG uAddressOfNames;
	for (ULONG uIndex = 0; uIndex < pExportDirectory->NumberOfNames; uIndex++, AddressOfNames++, AddressOfNameOrdinals++)
	{
		uAddressOfNames = *AddressOfNames;
		pSectionHeader = pOldSectionHeader;
		for (WORD Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
		{
			if (pSectionHeader->VirtualAddress <= uAddressOfNames &&
				uAddressOfNames <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
			{
				uOffset = uAddressOfNames - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
			}
		}
		FunName = (LPSTR)((ULONG)pBuffer + uOffset);
		if (FunName[0] == 'Z' && FunName[1] == 'w')
		{
			pSectionHeader = pOldSectionHeader;
			uOffset = (ULONG)AddressOfFunctions[*AddressOfNameOrdinals];
			for (WORD Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
			{
				if (pSectionHeader->VirtualAddress <= uOffset&&
					uOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
				{
					uNameOffset = uOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
				}
			}
			pFuncAddr = (PVOID)((ULONG)pBuffer + uNameOffset);
			uServerIndex = *(PULONG)((ULONG)pFuncAddr + 1);
			FunName[0] = 'N';
			FunName[1] = 't';

			if (!strcmp(szFuncName, FunName))
			{
				nOrder = (int)uServerIndex;
				break;
			}
		}
	}
	ExFreePoolWithTag(pBuffer, (ULONG)"NTDLL");
	ZwClose(FileHandle);

	return nOrder;
}

PVOID GetSSDTFuncAddrByName(const char* szFuncName)
{
	int  nOrder = GetSSDTOrderByName(szFuncName);
	if (-1 == nOrder) return NULL;

	return (PVOID)KeServiceDescriptorTable.ServiceTableBase[nOrder];

}
