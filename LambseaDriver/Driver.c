#pragma once
#include "Driver.h"
#include "ProcessProtect.h"
#include "FileProtect.h"

PDEVICE_OBJECT pDeviceObject;			// our driver object
UNICODE_STRING dev, dos;				// Driver registry paths

DWORD_PTR	TargetProcessBase = 0;		//Game's Base
ULONG		TargetProcessID   = 0;		//Game's PID
PEPROCESS   TargetEProcess    = NULL;   //Game's PEPROCESS


NTSTATUS KernelReadVirtualMemory(PVOID ReadFromAddress, PVOID CopiedToAddress, SIZE_T Size)
{
	if (TargetProcessID == 0)
		return STATUS_INVALID_PARAMETER;

	if (TargetEProcess == NULL)
		return STATUS_UNSUCCESSFUL;

	NTSTATUS ret = STATUS_UNSUCCESSFUL;

	__try
	{
		SIZE_T Bytes;
		ProbeForRead(ReadFromAddress, Size, sizeof(UCHAR));
		ret = MmCopyVirtualMemory
		(
			TargetEProcess,
			ReadFromAddress,
			PsGetCurrentProcess(),
			CopiedToAddress,
			Size,
			KernelMode,
			&Bytes
		);		
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}

	return ret;

}

NTSTATUS KernelWriteVirtualMemory(PVOID CopiedFromAddress, PVOID CopiedToAddress, SIZE_T Size)
{
	if (TargetProcessID == 0)
		return STATUS_INVALID_PARAMETER;

	if (TargetEProcess == NULL)
		return STATUS_UNSUCCESSFUL;

	NTSTATUS ret = STATUS_UNSUCCESSFUL;

	__try
	{
		SIZE_T Bytes;
		ProbeForRead(CopiedToAddress, Size, sizeof(UCHAR));
		ret = MmCopyVirtualMemory
		(
			PsGetCurrentProcess(),
			CopiedFromAddress,
			TargetEProcess,
			CopiedToAddress,
			Size,
			KernelMode,
			&Bytes
		);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}

	return ret;
}

NTSTATUS KernelGetProcessModuleBase(PVOID addressBuffer)
{

	if (TargetProcessID == 0)
		return STATUS_INVALID_PARAMETER;

	if (TargetEProcess == NULL)
		return STATUS_UNSUCCESSFUL;

	DWORD_PTR addr;

	__try
	{
		addr = (DWORD_PTR)PsGetProcessSectionBaseAddress(TargetEProcess);
		*(DWORD_PTR*)addressBuffer = addr;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(0, 0, "KernelGetProcessModuleBase failed\n");
		return GetExceptionCode();;
	}
	return STATUS_SUCCESS;
}

PEPROCESS KernelGetEProcess(ULONG ProcessID) {

	PEPROCESS eprocess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)ProcessID, &eprocess);
	if (NT_SUCCESS(status))
		return eprocess;
	else
		return NULL;

}

ULONG64 GetSystemModuleBase(char* lpModuleName)
{
	ULONG NeedSize, i, ModuleCount, BufferSize = 0x5000;
	PVOID pBuffer = NULL;
	PCHAR pDrvName = NULL;
	NTSTATUS Result;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;
	do
	{
		//分配内存
		pBuffer = kmalloc(BufferSize);
		if (pBuffer == NULL)
			return 0;
		//查询模块信息
		Result = ZwQuerySystemInformation(11, pBuffer, BufferSize, &NeedSize);
		if (Result == STATUS_INFO_LENGTH_MISMATCH)
		{
			kfree(pBuffer);
			BufferSize *= 2;
		}
		else if (!NT_SUCCESS(Result))
		{
			//查询失败则退出
			kfree(pBuffer);
			return 0;
		}
	} while (Result == STATUS_INFO_LENGTH_MISMATCH);
	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
	//获得模块的总数量
	ModuleCount = pSystemModuleInformation->Count;
	//遍历所有的模块
	for (i = 0; i < ModuleCount; i++)
	{
		if ((ULONG64)(pSystemModuleInformation->Module[i].Base) >(ULONG64)0x8000000000000000)
		{
			pDrvName = pSystemModuleInformation->Module[i].ImageName + pSystemModuleInformation->Module[i].ModuleNameOffset;
			if (_stricmp(pDrvName, lpModuleName) == 0)
				return (ULONG64)pSystemModuleInformation->Module[i].Base;
		}
	}
	kfree(pBuffer);
	return 0;
}

// IOCTL Call Handler function
NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS Status;
	ULONG BytesIO = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	// Code received from user space
	ULONG ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (ControlCode == IO_READ_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PKERNEL_READ_REQUEST ReadInput = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		Status = KernelReadVirtualMemory
		(
			(PVOID)ReadInput->TargetAddress,
			(PVOID)ReadInput->ResponseAddress,
			ReadInput->Size
		);
	
		DbgPrintEx(0, 0, "Readed Process ID:  %lu, For Address %#010x \n", TargetProcessID, ReadInput->TargetAddress);
		BytesIO = sizeof(KERNEL_READ_REQUEST);
	}
	else if (ControlCode == IO_WRITE_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PKERNEL_WRITE_REQUEST WriteInput = (PKERNEL_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		Status = KernelWriteVirtualMemory
		(
			(PVOID)WriteInput->CopiedFromAddress,
			(PVOID)WriteInput->TargetAddress,
			WriteInput->Size
		);

		DbgPrintEx(0, 0, "Writted Process ID:  %lu, For Address %#010x Size %d \n", TargetProcessID, WriteInput->TargetAddress, WriteInput->Size);
		BytesIO = sizeof(KERNEL_WRITE_REQUEST);
	}
	else if (ControlCode == IO_GET_MODULE_REQUEST)
	{
		PDWORD_PTR OutPut = Irp->AssociatedIrp.SystemBuffer;
		Status = KernelGetProcessModuleBase(&TargetProcessBase);
		*OutPut = TargetProcessBase;
		DbgPrintEx(0, 0, "Recieved IO_GET_MODULE_REQUEST , base 0x%I64X \n", TargetProcessBase);
		BytesIO = sizeof(*OutPut);
	}
	else if (ControlCode == IO_Init_REQUEST)
	{
		PULONG receivedTargetProcessId = Irp->AssociatedIrp.SystemBuffer;
		TargetProcessID = *receivedTargetProcessId;
		TargetEProcess = KernelGetEProcess(TargetProcessID);
		DbgPrintEx(0, 0, "Recieved IO_Init_REQUEST , Target  Process PID %d \n", *receivedTargetProcessId);
		DbgPrintEx(0, 0, "Recieved IO_Init_REQUEST , Sender  Process PID %d \n", PtrToUlong(PsGetCurrentProcessId()));

		if(TargetEProcess!=NULL)
			Status = STATUS_SUCCESS;
		else
			Status = STATUS_UNSUCCESSFUL;
	}
	else if (ControlCode == IO_PROTECT_REQUEST)
	{
		PULONG receivedProcessIdToBeProtected = Irp->AssociatedIrp.SystemBuffer;
		ProtectProcess(*receivedProcessIdToBeProtected);
		DbgPrintEx(0, 0, "Recieved IO_PROTECT_REQUEST , Target  Process PID %d \n", *receivedProcessIdToBeProtected);
		Status = STATUS_SUCCESS;
	}
	else
	{
		 // if the code is unknown
		Status = STATUS_INVALID_PARAMETER;
		BytesIO = 0;
		DbgPrintEx(0, 0, "IoControl STATUS_INVALID_PARAMETER Recevied\n");
	}


	// Complete the request
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	
	return Status;
}

// Driver Entrypoint
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	DbgPrintEx(0, 0, "Driver Loaded\n");

	//PsSetLoadImageNotifyRoutine(ImageLoadCallback);

	RtlInitUnicodeString(&dev, DEVICE_NAME);
	RtlInitUnicodeString(&dos, DEVICE_DOS_NAME);

	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&dos, &dev);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCall;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	pDriverObject->DriverUnload = UnloadDriver;

	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	if (SetupProcessCallBack())
		DbgPrintEx(0, 0, "Driver obCallBack Registered\n");
	else
		DbgPrintEx(0, 0, "Driver obCallBack Failed to Register\n");

	if (NT_SUCCESS(SetupMinifilter(pDriverObject, pRegistryPath)))
	{
		DbgPrintEx(0, 0, "Driver File System MiniFilter Registered\n");
		NTSTATUS ret = StartMinifilter();
		if(NT_SUCCESS(ret))
			DbgPrintEx(0, 0, "Driver File System MiniFilter Started\n");
		else
			DbgPrintEx(0, 0, "Driver File System MiniFilter Failed to Be Started\n");
	}
	else
		DbgPrintEx(0, 0, "Driver file filter Failed to Register\n");

	return STATUS_SUCCESS;
}

//Unload Event
NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{

	DbgPrintEx(0, 0, "Driver Unload.\n");
	//PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageLoadCallback);
	RemoveProcessCallBack();

	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObject->DeviceObject);

	return STATUS_SUCCESS;
}

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	DbgPrintEx(0, 0, "Create Device Complete\n");

	return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	//CLEAN UP
	if(TargetEProcess!=NULL)
		ObDereferenceObject(TargetEProcess);

	TargetProcessID   = 0;
	TargetProcessBase = 0;
	TargetEProcess    = NULL;

	DbgPrintEx(0, 0, "Close Device Complete\n");
	return STATUS_SUCCESS;
}
