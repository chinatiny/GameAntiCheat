#include "AntiOpenMore.h"
#include "AntiCheat.h"

void AntiOpenMore()
{
	HANDLE hMutex = NULL;
	hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, _T("llkmutex"));
	if (NULL == hMutex)
	{
		CreateMutex(NULL, TRUE, _T("llkmutex"));
	}
	else
	{
		CloseHandle(hMutex);
		MessageBox(NULL, _T("该程序不允许多开"), _T("提示"), MB_OK);
		ExitProcess(1);
	}
}
