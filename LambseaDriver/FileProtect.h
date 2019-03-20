#pragma once
#include <Fltkernel.h>

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>

#include <dontuse.h>
#include <suppress.h>

#define Debug_Out 0
#if Debug_Out
#define DbgPrintEx //
#define DbgPrint //
#endif // Debug_Out

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

NTSTATUS
FFUnload
(
	__in FLT_FILTER_UNLOAD_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
FFPreCreate
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
FFPostCreate
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
FFPreRead
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
FFPostRead
(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
);

NTSTATUS SetupMinifilter(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS StartMinifilter(void);
NTSTATUS CloseMinifilter(void);
NTSTATUS AddMoniteringFile(const wchar_t* fileName);