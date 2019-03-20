#pragma once
#include "FileProtect.h"


PFLT_FILTER g_pFilterHandle = NULL;

//operation registration
const FLT_OPERATION_REGISTRATION Callbacks[] =
{
	{
		IRP_MJ_CREATE,
		0,
		FFPreCreate,
		FFPostCreate
	},
	{
		IRP_MJ_READ,
		0,
		FFPreRead,
		FFPostRead
	},
	{
		IRP_MJ_SET_INFORMATION,
		0,
		FFPreRead,
		FFPostRead
	},
	{
		IRP_MJ_WRITE,
		0,
		FFPreRead,
		FFPostRead
	},
	{
		IRP_MJ_OPERATION_END
	}
};

NTSTATUS FFUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);
	if(g_pFilterHandle!=NULL)
		FltUnregisterFilter(g_pFilterHandle);
	g_pFilterHandle = NULL;
	DbgPrintEx(0, 0, "[MiniFilter][MiniFilter Unloaded]\n");
	return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS FFPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID * CompletionContext)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PFLT_FILE_NAME_INFORMATION nameInfo;
	UCHAR MajorFunction = Data->Iopb->MajorFunction;
	//ULONG Options = Data->Iopb->Parameters.Create.Options;

	if (IRP_MJ_CREATE == MajorFunction && 
		NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
	{
		//如果解析文件信息成功
		if (NT_SUCCESS(FltParseFileNameInformation(nameInfo)))
		{
			if (NULL != wcsstr(nameInfo->Name.Buffer, L"Lambsea.sys"))  // 检查是不是要保护的文件
			{
				DbgPrintEx(0, 0, "In FFPreCreate(), FilePath{%wZ} is forbided.", &nameInfo->Name);
				FltReleaseFileNameInformation(nameInfo);
				//return FLT_PREOP_COMPLETE;
				return FLT_PREOP_DISALLOW_FASTIO;
			}
		}
		FltReleaseFileNameInformation(nameInfo);
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS FFPreRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID * CompletionContext)
{

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PFLT_FILE_NAME_INFORMATION nameInfo;
	//直接获得文件名并检查
	if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
	{
		if (NT_SUCCESS(FltParseFileNameInformation(nameInfo)))
		{
			if (NULL != wcsstr(nameInfo->Name.Buffer, L"Lambsea.sys"))  // 检查是不是要保护的文件
			{
				DbgPrintEx(0, 0, "In FFPreRead(), FilePath{%wZ} is forbided.", &nameInfo->Name);
				FltReleaseFileNameInformation(nameInfo);
				return FLT_PREOP_DISALLOW_FASTIO;
			}
		}
		FltReleaseFileNameInformation(nameInfo);
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//unused
FLT_POSTOP_CALLBACK_STATUS
FFPostCreate
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
) 
{
	DbgPrintEx(0, 0, "[MiniFilter][FFPostCreate]\n");
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
FFPostRead
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
) 
{
	DbgPrintEx(0, 0, "[MiniFilter][FFPostRead]\n");
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

//run once
NTSTATUS SetupMinifilter(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	if (g_pFilterHandle != NULL)
		return STATUS_ALREADY_INITIALIZED;

	const FLT_REGISTRATION FilterRegistration =
	{
		sizeof(FLT_REGISTRATION),           //  Size
		FLT_REGISTRATION_VERSION,           //  Version
		0,                                  //  Flags
		NULL,                               //  Context
		Callbacks,                          //  Operation callbacks
		FFUnload,                           //  MiniFilterUnload
		NULL,								//  InstanceSetup
		NULL,								//  InstanceQueryTeardown
		NULL,								//  InstanceTeardownStart
		NULL,								//  InstanceTeardownComplete
		NULL,                               //  GenerateFileName
		NULL,                               //  GenerateDestinationFileName
		NULL                                //  NormalizeNameComponent
	};

	NTSTATUS status = FltRegisterFilter
	(
		DriverObject,
		&FilterRegistration,
		&g_pFilterHandle
	);

	if (status != STATUS_SUCCESS)
		DbgPrintEx(0, 0, "[Minifilter][Cannot register filter, error code 0x%I64X]",status);

	return status;
}

NTSTATUS StartMinifilter(void)
{
	NTSTATUS status = FltStartFiltering(g_pFilterHandle);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "[Minifilter]FltStartFiltering Failed with code 0x%I64X\n", status);
		FltUnregisterFilter(g_pFilterHandle);
		g_pFilterHandle = NULL;
		return status;
	}

	PFLT_VOLUME VolumeList[10];
	ULONG NumberVolumesReturned = 0;
	FLT_VOLUME_PROPERTIES volprop;
	ULONG lenght_needed;
	UNICODE_STRING volume_name;
	wchar_t buffer[512];
	PFLT_INSTANCE ret_instance;
	UNICODE_STRING alt;

	RtlInitUnicodeString(&alt, L"320533");


	status = FltEnumerateVolumes(g_pFilterHandle, VolumeList, 10, &NumberVolumesReturned);

	volume_name.Buffer = buffer;
	volume_name.Length = 0;
	volume_name.MaximumLength = 512;

	DbgPrintEx(0, 0, "[MiniFilter][NumberVolumesReturned %d]", NumberVolumesReturned);

	if(NT_SUCCESS(status))
	for (ULONG i = 0; i < NumberVolumesReturned; i++)
	{
		FltGetVolumeProperties(VolumeList[i], &volprop, sizeof(FLT_VOLUME_PROPERTIES), &lenght_needed);
		FltGetVolumeName(VolumeList[i], &volume_name, NULL);


		switch (volprop.DeviceType)
		{
		case FILE_DEVICE_DFS_FILE_SYSTEM:
		case FILE_DEVICE_DISK_FILE_SYSTEM:
		case FILE_DEVICE_FILE_SYSTEM:
		case FILE_DEVICE_NETWORK_FILE_SYSTEM:
			DbgPrintEx(0, 0, "[MiniFilter][Volume name %ws]", volume_name.Buffer);
			
			status = FltAttachVolumeAtAltitude(g_pFilterHandle, VolumeList[i], &alt, NULL, &ret_instance);

			if (!NT_SUCCESS(status))
				DbgPrintEx(0, 0, "[MiniFilter][FltAttachVolumeAtAltitude Failed with Code %I64X]", status);
			else
				FltObjectDereference(ret_instance);

			break;
		default:
			break;
		}


	}
	else
	{
		DbgPrintEx(0, 0, "FltEnumerateVolumes Failed");
	}
	

	return status;
}

NTSTATUS CloseMinifilter(void)
{
	return FFUnload((FLT_FILTER_UNLOAD_FLAGS)0);
}
