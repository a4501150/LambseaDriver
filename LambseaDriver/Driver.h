#pragma once 

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>

#define DEVICE_NAME L"\\Device\\JYAV"
#define DEVICE_DOS_NAME L"\\DosDevices\\JYAV"


// Request to retrieve initialize from kernel space
#define IO_Init_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x05240 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to retrieve the base address of process in csgo.exe from kernel space
#define IO_GET_MODULE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x05241 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to read virtual user memory (memory of a program) from kernel space
#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x05242 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write virtual user memory (memory of a program) from kernel space
#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x05243 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to protect a process from kernel space
#define IO_PROTECT_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x05244 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


#define kmalloc(_s)	ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')
#define kfree(_p)	ExFreePool(_p)


#define Debug_Out 0
#if Debug_Out
#define DbgPrintEx //
#define DbgPrint //
#endif // Debug_Out

//Undocumented APIs
NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

NTKERNELAPI
PVOID
PsGetProcessSectionBaseAddress(
	__in PEPROCESS Process
);


NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation
(
	IN ULONG	SystemInformationClass,
	OUT PVOID	SystemInformation,
	IN ULONG	Length,
	OUT PULONG	ReturnLength
);

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
	ULONG Unknow1;
	ULONG Unknow2;
	ULONG Unknow3;
	ULONG Unknow4;
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	char ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;//内核中以加载的模块的个数
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY64 InLoadOrderLinks;
	ULONG64 __Undefined1;
	ULONG64 __Undefined2;
	ULONG64 __Undefined3;
	ULONG64 NonPagedDebugInfo;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG   Flags;
	USHORT  LoadCount;
	USHORT  __Undefined5;
	ULONG64 __Undefined6;
	ULONG   CheckSum;
	ULONG   __padding1;
	ULONG   TimeDateStamp;
	ULONG   __padding2;
}KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;


// datatype for read request
typedef struct _KERNEL_READ_REQUEST
{
	DWORD_PTR TargetAddress;
	DWORD_PTR ResponseAddress;
	ULONG Size;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

// datatype for write request
typedef struct _KERNEL_WRITE_REQUEST
{
	DWORD_PTR TargetAddress;
	DWORD_PTR CopiedFromAddress;
	ULONG Size;
} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;


PEPROCESS KernelGetEProcess(ULONG ProcessID);
NTSTATUS KernelReadVirtualMemory(PVOID ReadFromAddress, PVOID CopiedToAddress, SIZE_T Size);
NTSTATUS KernelWriteVirtualMemory(PVOID CopiedFromAddress, PVOID CopiedToAddress, SIZE_T Size);
NTSTATUS KernelGetProcessModuleBase(PVOID addressBuffer);

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp);