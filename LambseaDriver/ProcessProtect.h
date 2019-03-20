#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>

#define Debug_Out 0
#if Debug_Out
#define DbgPrintEx //
#define DbgPrint //
#endif // Debug_Out


PVOID ObCallBackHandle = NULL;
ULONG ProtectedProcessID = 0;

#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)  

OB_PREOP_CALLBACK_STATUS ProcessAccessCallBackHandler(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{

	if (ProtectedProcessID == 0)
		return OB_PREOP_SUCCESS;

	UNREFERENCED_PARAMETER(RegistrationContext);

	PEPROCESS OpenedProcess  = (PEPROCESS)pOperationInformation->Object,
			  CurrentProcess = PsGetCurrentProcess();

	ULONG     ulProcessId = PtrToUlong(PsGetProcessId(OpenedProcess)); //process being openned

	// filter operations 
	if (ulProcessId != ProtectedProcessID)
		return OB_PREOP_SUCCESS;

	// Allow operations from the process itself
	if (CurrentProcess == OpenedProcess)
		return OB_PREOP_SUCCESS;

	// Remove access bits from open access mask.
	else if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
	{
		DbgPrintEx(0, 0, "CallBack Triggered. Limited it to PROCESS_TERMINATE!");
		pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (PROCESS_TERMINATE);
	}

	return OB_PREOP_SUCCESS;

}

VOID ProtectProcess(ULONG PID) 
{
	ProtectedProcessID = PID;
}

VOID UnProtectProcess()
{
	ProtectedProcessID = 0;
}

BOOLEAN SetupProcessCallBack()
{
	OB_OPERATION_REGISTRATION opRegistrations[1] = { { 0 } };;
	opRegistrations[0].ObjectType = PsProcessType;
	opRegistrations[0].Operations = OB_OPERATION_HANDLE_CREATE;
	opRegistrations[0].PreOperation = ProcessAccessCallBackHandler;

	OB_CALLBACK_REGISTRATION obCallBackReg = { 0 };
	obCallBackReg.Version = ObGetFilterVersion();
	obCallBackReg.OperationRegistrationCount = 1;
	obCallBackReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obCallBackReg.Altitude, L"320524");
	obCallBackReg.OperationRegistration = opRegistrations;

	NTSTATUS status = ObRegisterCallbacks(&obCallBackReg, &ObCallBackHandle);
	BOOLEAN ret = NT_SUCCESS(status);

	if(!ret)
		DbgPrintEx(0, 0, "SetupProcessCallBack Failed Last Error 0x%I32X\n", status);
	else
		DbgPrintEx(0, 0, "SetupProcessCallBack Success\n");
	
	return ret;

}

VOID RemoveProcessCallBack()
{
	if (ObCallBackHandle != NULL)
	{
		ObUnRegisterCallbacks(ObCallBackHandle);
		ObCallBackHandle = NULL;
	}
}