#include "AntiCheatDriver.h"
#include "AntiArkTool.h"
#include "AntiWorker.h"
#include "Router.h"
#include "Timer.h"
#include "UnDocoumentSpec.h"
#include "ProcessProtected.h"
#include "IDT.h"

extern int GetMsgSize(int nMsgNo);
//
VOID DriverUnload(PDRIVER_OBJECT pDriver);
NTSTATUS CreateAndClose(PDEVICE_OBJECT objDeivce, PIRP pIrp);
NTSTATUS CommonProc(PDEVICE_OBJECT objDeivce, PIRP pIrp);
NTSTATUS HandleRead(PDEVICE_OBJECT objDeivce, PIRP pIrp);
NTSTATUS HandleWrite(PDEVICE_OBJECT objDeivce, PIRP pIrp);
VOID ProcessNotifyRoutine(
	IN HANDLE        ParentId,
	IN HANDLE        ProcessId,
	IN BOOLEAN        Create
	);

NTSTATUS DriverEntry(
	PDRIVER_OBJECT pDriver,
	PUNICODE_STRING pPath
	)
{
	NTSTATUS status = 0;
	KdPrint(("AntiCheatDriver Load\n"));
	AntiArk(pDriver);
	GetEnableFlagAddr();
	UNICODE_STRING pDeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
	UNICODE_STRING pSymbolLinkName = RTL_CONSTANT_STRING(SYSBOL_LINK_NAME);
	PDEVICE_OBJECT pDevice = NULL;
	status = IoCreateDevice(
		pDriver,
		0,
		&pDeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&pDevice
		);
	if (NT_SUCCESS(status) == FALSE)
	{
		return status;
	}
	pDevice->Flags |= DO_BUFFERED_IO;
	IoCreateSymbolicLink(&pSymbolLinkName, &pDeviceName);

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriver->MajorFunction[i] = CommonProc;
	}
	pDriver->DriverUnload = DriverUnload;

	//保证ObRegisterCallbacks调用成功
	PLDR_DATA_TABLE_ENTRY ldr;
	ldr = (PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	ldr->Flags |= 0x20;//加载驱动的时候会判断此值。必须有特殊签名才行，增加0x20即可。否则将调用失败   

	//工作线程的自选锁
	KeInitializeSpinLock(&g_spinWorkState);
	//初始化输出队列
	InitMsgQue(&g_outQue);
	//IO定时器
	IoInitializeTimer(pDevice, TimerProc, NULL);
	IoStartTimer(pDevice);
	//idthook
	InstallIDTHook();
	//安装一个进程监控回调
	PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, FALSE);

	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	UNICODE_STRING pSymbolLinkName = RTL_CONSTANT_STRING(SYSBOL_LINK_NAME);
	IoDeleteSymbolicLink(&pSymbolLinkName);
	IoDeleteDevice(pDriver->DeviceObject);
	//卸载idthook
	//UnistallIDTHook();
	//设置工作状态结束
	SetWorkState(FALSE);
	//等待线程正常退出
	PETHREAD pThread = NULL;
	PsLookupThreadByThreadId(g_workClientID.UniqueThread, &pThread);
	LARGE_INTEGER timout;
	timout.HighPart = 0xFFFFFFFF;
	KeWaitForSingleObject(pThread, Executive, KernelMode, FALSE, &timout);
	//卸载回调
	PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);
	KdPrint(("DriverUnload\n"));
}

NTSTATUS CommonProc(PDEVICE_OBJECT objDeivce, PIRP pIrp)
{
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);
	switch (pStack->MajorFunction)
	{
	case IRP_MJ_CREATE:
	case IRP_MJ_CLOSE:
		CreateAndClose(objDeivce, pIrp);
		break;
	case IRP_MJ_READ:
		HandleRead(objDeivce, pIrp);
		break;
	case IRP_MJ_WRITE:
		HandleWrite(objDeivce, pIrp);
		break;
	default:
		pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		pIrp->IoStatus.Information = 0;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	}
	return STATUS_SUCCESS;
}

NTSTATUS HandleRead(PDEVICE_OBJECT objDeivce, PIRP pIrp)
{
	UCHAR * pIOBuff = NULL;
	if (pIrp->AssociatedIrp.SystemBuffer != NULL)
	{
		pIOBuff = pIrp->AssociatedIrp.SystemBuffer;
	}
	else if (pIrp->MdlAddress != NULL)
	{
		pIOBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
	}
	//
	if (!IsMsgQueEmpty(&g_outQue))
	{
		MsgNode* node = PopMsgQue(&g_outQue);
		memcpy(pIOBuff, node, GetMsgSize(node->nMsgNo) + sizeof(struct __MsgNode*) + sizeof(int));
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = GetMsgSize(node->nMsgNo) + sizeof(struct __MsgNode*) + sizeof(int);
		ExFreePool(node);
	}
	else
	{
		pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		pIrp->IoStatus.Information = 0;
	}
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CreateAndClose(PDEVICE_OBJECT objDeivce, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS HandleWrite(PDEVICE_OBJECT objDeivce, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(objDeivce);
	UCHAR * pIOBuff = NULL;
	if (pIrp->AssociatedIrp.SystemBuffer != NULL)
	{
		pIOBuff = pIrp->AssociatedIrp.SystemBuffer;
	}
	else if (pIrp->MdlAddress != NULL)
	{
		pIOBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
	}
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);
	if (Router((char*)pIOBuff, pStack->Parameters.Write.Length))
	{
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = pStack->Parameters.Write.Length;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	}
	else
	{
		pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		pIrp->IoStatus.Information = pStack->Parameters.Write.Length;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	}

	return STATUS_SUCCESS;
}

VOID ProcessNotifyRoutine(
	IN HANDLE        ParentId,
	IN HANDLE        ProcessId,
	IN BOOLEAN        Create
	)
{
	if (!Create)
	{
		if (g_needProtectObj.uGameProcessID != 0 && (HANDLE)g_needProtectObj.uGameProcessID == ProcessId)
		{
			//设置工作线程工作标示为结束
			UnRegisterProtected();
		}
	}
}
