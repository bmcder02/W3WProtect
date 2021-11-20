#include "file.h"

/*************************************************************************
	Mini-Filter	Definitions
*************************************************************************/
#define PTDEF_MF_TAG_PROCESS_NAME	'NPDP'
#define PTDEF_MF_TAG_COMMAND_LINE	'LCDP'

#define PTDEF_MF_LENGTH_PROCESS_NAME 500
#define PTDEF_MF_LENGTH_COMMAND_LINE 128
#define PTDEF_MF_LENGTH_FILE_NAME 1024 
#define PTDEF_MF_LENGTH_PARENT_DIRECTORY 1024

/*************************************************************************
	Mini-Filter	Functions
*************************************************************************/

FLT_PREOP_CALLBACK_STATUS
PtPreCreateOp(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

	Whenever an operation attempts to create a file, this routine is called.
	This gives us an oppertunity to see if it is being created by the W3WP process,
	and prevent it if it is not within a whitelisted directory.

Arguments:

	Data		- Pointer to the filter callback data that is passed to us.

	FltObjects	- Pointer to the FLT_RELATED_OBJECTS data structure containing
				opaque handles to this filter, instance and it's associated volume
				and file object.

	Completion Context - If this callback routine returns FLT_PREOP_SUCCESS_WITH_CALLBACK or
				FLT_PREOP_SYNCHRONIZE, this parameter is an optional context pointer to be
				passed to the corresponding post-operation callback routine. Otherwise,
				it must be NULL.

Return Value:

	FLT_PREOP_SYNCHRONIZE - PostCreate needs to be called back synchronizedly.
	FLT_PREOP_SUCCESS_NO_CALLBACK - PostCreate does not need to be called.

--*/
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects);

	PAGED_CODE();

	NTSTATUS status;
	NTSTATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	ULONG retSize;


	// 
	// Instantly dismiss Kernel Code, preventing any holdups. 
	//
	if (Data->RequestorMode == KernelMode)
		return returnStatus;

	PUNICODE_STRING processName = (UNICODE_STRING*)ExAllocatePoolWithTag(
		PagedPool,
		PTDEF_MF_LENGTH_PROCESS_NAME,
		PTDEF_MF_TAG_PROCESS_NAME
	);
	if (!processName)
		return returnStatus;
	RtlZeroMemory(processName, PTDEF_MF_LENGTH_PROCESS_NAME);

	status = ZwQueryInformationProcess(
		NtCurrentProcess(),					// Process Handle
		ProcessImageFileName,				// PROCESSINFOCLASS
		processName,						// Buffer
		PTDEF_MF_LENGTH_PROCESS_NAME,		// SizeOfBuffer
		&retSize							// Return size. 
	);
	if (!NT_SUCCESS(status) ||
		retSize == 0 ||
		processName->Length == 0)
		goto Cleanup;

	//
	// If the process isn't w3wp,
	// leave it alone.
	//
	if (!PtContainsUnicodeString(processName, L"w3wp"))
		goto Cleanup;

	//
	// Get the filename. 
	//
	PFLT_FILE_NAME_INFORMATION nameInfo;

	status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
		&nameInfo
	);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	status = FltParseFileNameInformation(nameInfo);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	if (nameInfo->ParentDir.Length == 0)
		goto Cleanup;

	for (ULONG i = 0; i < Globals.ConfigDirSize; i++)
	{
		// if item in whitelist, go to cleanup.
		if (wcsstr(nameInfo->ParentDir.Buffer, Globals.ConfigWhiteListedDirectory[i]->Buffer) == NULL)
			goto Cleanup;
	}

	//
	// Copy the filename to a buffer and null terminate it. 
	//
	ULONG BytesToCopy = PTDEF_MF_LENGTH_FILE_NAME * sizeof(WCHAR);
	WCHAR FileName[PTDEF_MF_LENGTH_FILE_NAME];
	RtlZeroBytes(
		FileName,
		PTDEF_MF_LENGTH_FILE_NAME * sizeof(WCHAR)
	);
	if (nameInfo->Name.Length <= BytesToCopy)
		BytesToCopy = nameInfo->Name.Length;

	RtlCopyMemory(
		FileName,
		nameInfo->Name.Buffer,
		BytesToCopy
	);

	FileName[PTDEF_MF_LENGTH_FILE_NAME / sizeof(WCHAR)] = L'\0';

	
	//
	// Copy the parent directory to a buffer and null terminate it. 
	//
	BytesToCopy = PTDEF_MF_LENGTH_PARENT_DIRECTORY * sizeof(WCHAR);
	WCHAR ParentDir[PTDEF_MF_LENGTH_PARENT_DIRECTORY];
	RtlZeroMemory(
		ParentDir,
		PTDEF_MF_LENGTH_PARENT_DIRECTORY * sizeof(WCHAR)
	);
	if (nameInfo->ParentDir.Length <= BytesToCopy)
		BytesToCopy = nameInfo->ParentDir.Length;

	RtlCopyMemory(
		ParentDir,
		nameInfo->ParentDir.Buffer,
		BytesToCopy
	);
	ParentDir[PTDEF_MF_LENGTH_FILE_NAME / sizeof(WCHAR)] = L'\0';


	if (!Globals.Enforced)
	{
		EventWriteFileCreateBlock_Passive(
			NULL,
			HandleToULong(NtCurrentProcess()),
			FileName,
			ParentDir
		);
		goto Cleanup;
	}

	EventWriteFileCreateBlock_Enforced(
		NULL,
		HandleToULong(NtCurrentProcess()),
		FileName,
		ParentDir
	);

	Data->IoStatus.Status = STATUS_ACCESS_DENIED;
	returnStatus = FLT_PREOP_COMPLETE;


Cleanup:

	ExFreePoolWithTag(
		processName,
		PTDEF_MF_TAG_PROCESS_NAME
	);

	return returnStatus;
}

FLT_PREOP_CALLBACK_STATUS
PtPreWriteOp(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

	Whenever an operation attempts to write a file, this routine is called.
	This gives us an oppertunity to see if it is being created by the W3WP process,
	and prevent it if it is not within a whitelisted directory.

Arguments:

	Data		- Pointer to the filter callback data that is passed to us.

	FltObjects	- Pointer to the FLT_RELATED_OBJECTS data structure containing
				opaque handles to this filter, instance and it's associated volume
				and file object.

	Completion Context - If this callback routine returns FLT_PREOP_SUCCESS_WITH_CALLBACK or
				FLT_PREOP_SYNCHRONIZE, this parameter is an optional context pointer to be
				passed to the corresponding post-operation callback routine. Otherwise,
				it must be NULL.

Return Value:

	FLT_PREOP_SYNCHRONIZE - PostCreate needs to be called back synchronizedly.
	FLT_PREOP_SUCCESS_NO_CALLBACK - PostCreate does not need to be called.

--*/
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects);

	PAGED_CODE();

	NTSTATUS status;
	NTSTATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	ULONG retSize;

	// 
	// Instantly dismiss Kernel Code, preventing any holdups. 
	//
	if (Data->RequestorMode == KernelMode)
		return returnStatus;

	PUNICODE_STRING processName = (UNICODE_STRING*)ExAllocatePoolWithTag(
		PagedPool,
		PTDEF_MF_LENGTH_PROCESS_NAME,
		PTDEF_MF_TAG_PROCESS_NAME
	);
	if (!processName)
		return returnStatus;
	RtlZeroMemory(processName, PTDEF_MF_LENGTH_PROCESS_NAME);

	status = ZwQueryInformationProcess(
		NtCurrentProcess(),					// Process Handle
		ProcessImageFileName,				// PROCESSINFOCLASS
		processName,						// Buffer
		PTDEF_MF_LENGTH_PROCESS_NAME,		// SizeOfBuffer
		&retSize								// Return size. 
	);
	if (!NT_SUCCESS(status) ||
		retSize == 0 ||
		processName->Length == 0)
		goto Cleanup;

	//
	// If the process isn't w3wp,
	// leave it alone.
	//
	if (!PtContainsUnicodeString(processName, L"w3wp"))
		goto Cleanup;

	//
	// Get the filename. 
	//
	PFLT_FILE_NAME_INFORMATION nameInfo;

	status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
		&nameInfo
	);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	status = FltParseFileNameInformation(nameInfo);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	for (ULONG i = 0; i < Globals.ConfigDirSize; i++)
	{
		// if item in whitelist, go to cleanup.
		if (wcsstr(nameInfo->ParentDir.Buffer, Globals.ConfigWhiteListedDirectory[i]->Buffer) == NULL)
			goto Cleanup;
	}

	ULONG BytesToCopy = PTDEF_MF_LENGTH_FILE_NAME * sizeof(WCHAR);
	WCHAR FileName[PTDEF_MF_LENGTH_FILE_NAME];
	RtlZeroMemory(
		FileName,
		PTDEF_MF_LENGTH_FILE_NAME * sizeof(WCHAR)
	);
	if (nameInfo->Name.Length <= BytesToCopy)
		BytesToCopy = nameInfo->Name.Length;

	RtlCopyMemory(
		FileName,
		nameInfo->Name.Buffer,
		BytesToCopy
	);

	//
	// Null terminate the last byte.
	//
	FileName[PTDEF_MF_LENGTH_FILE_NAME / sizeof(WCHAR)] = L'\0';

	BytesToCopy = PTDEF_MF_LENGTH_PARENT_DIRECTORY * sizeof(WCHAR);
	WCHAR ParentDir[PTDEF_MF_LENGTH_PARENT_DIRECTORY];
	RtlZeroMemory(
		ParentDir,
		PTDEF_MF_LENGTH_PARENT_DIRECTORY * sizeof(WCHAR)
	);
	if (nameInfo->ParentDir.Length <= BytesToCopy)
		BytesToCopy = nameInfo->ParentDir.Length;

	RtlCopyMemory(
		ParentDir,
		nameInfo->ParentDir.Buffer,
		BytesToCopy
	);

	//
	// Null terminate the last byte.
	//
	ParentDir[PTDEF_MF_LENGTH_FILE_NAME / sizeof(WCHAR)] = L'\0';


	if (!Globals.Enforced)
	{
		EventWriteFileWriteBlock_Passive(
			NULL,
			HandleToULong(NtCurrentProcess()),
			FileName,
			ParentDir
		);
		goto Cleanup;
	}

	EventWriteFileWriteBlock_Enforced(
		NULL,
		HandleToULong(NtCurrentProcess()),
		FileName,
		ParentDir
	);

	// ToDo - Compare paths against whitelist. 
	Data->IoStatus.Status = STATUS_ACCESS_DENIED;
	returnStatus = FLT_PREOP_COMPLETE;


Cleanup:

	ExFreePoolWithTag(
		processName,
		PTDEF_MF_TAG_PROCESS_NAME
	);

	return returnStatus;
}

