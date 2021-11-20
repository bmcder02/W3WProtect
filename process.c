/*++

Module Name:

	process.c

Abstract:

	Contains the process functionality for W3WProtect. This includes the
	on notify callback to handle new processes being created.

Environment:

	Kernel

--*/

#include "process.h"

/*************************************************************************
	Process Notification Defines
*************************************************************************/
#define PTDEF_PROC_TAG_PROCESS_NAME	'NPDP'
#define PTDEF_PROC_TAG_COMMAND_LINE	'LCDP'

#define PTDEF_PROC_LENGTH_PROCESS_NAME 500
#define PTDEF_PROC_LENGTH_COMMAND_LINE 128

/*************************************************************************
	Process Notification Functions
*************************************************************************/
void PtOnProcessNotify(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
)
/*++

Routine Description:

	Monitors process creation events from W3WP, and prevent programs from
	executing outsides of the whitelist.

	The idea is to prevent unapproved software from executing, potentially
	through web exploitaiton.

Arguments:

	Process		- The executive representation of the process.

	ProcessId	- A handle of the process. (In kernel, ID == Handle)

	CreateInfo	- Details for the process being created. NULL if the process
				is being terminated.

Returns:

	None.

--*/
{
	UNREFERENCED_PARAMETER(Process);

	// Not interested in Processes that are closing. 
	if (!CreateInfo)
		return;

	//
	// Allocate the memory and zero it for the strings. 
	// ToDo		- See how to do the comparisons with WCHAR[] so I don't need the
	//			unicode strings. 
	//
	PUNICODE_STRING parentProcessName = (UNICODE_STRING*)ExAllocatePoolWithTag(
		PagedPool,
		PTDEF_PROC_LENGTH_PROCESS_NAME,
		PTDEF_PROC_TAG_PROCESS_NAME
	);
	if (parentProcessName == NULL)
		return;
	RtlZeroMemory(parentProcessName, PTDEF_PROC_LENGTH_PROCESS_NAME);

	PUNICODE_STRING processName = (UNICODE_STRING*)ExAllocatePoolWithTag(
		PagedPool,
		PTDEF_PROC_LENGTH_PROCESS_NAME,
		PTDEF_PROC_TAG_PROCESS_NAME
	);
	if (!processName)
	{
		ExFreePoolWithTag(parentProcessName, PTDEF_PROC_TAG_PROCESS_NAME);
		return;
	}
	RtlZeroMemory(
		processName,
		PTDEF_PROC_LENGTH_PROCESS_NAME
	);

	//
	// Get the PEPROCESS from the parent process ID.
	// With the PEProcess get the parent Ah,process name.
	//
	PEPROCESS parentProcess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(
		CreateInfo->ParentProcessId,
		&parentProcess
	);

	if (!NT_SUCCESS(status))
		goto Cleanup;

	status = SeLocateProcessImageName(
		parentProcess,
		&parentProcessName
	);

	if (!NT_SUCCESS(status))
		goto Cleanup;

	if (!parentProcessName->Buffer)
		goto Cleanup;

	//
	// If W3WP is not the parent process, we don't care.
	//
	if (!wcsstr(parentProcessName->Buffer, L"w3wp"))
		return;

	//
	// Get the Process Name from the PEPROCESS.
	//
	status = SeLocateProcessImageName(
		Process,
		&processName
	);
	if (!NT_SUCCESS(status))
		return;

	//
	// If in white list, leave it alone.  
	//
	for (ULONG i = 0; i < Globals.ConfigProcessSize; i++)
	{
		if (wcsstr(processName->Buffer, Globals.ConfigWhitelistedProcesses[i]->Buffer) != NULL)
		{
			goto Cleanup;
		}
	}

	WCHAR procName[PTDEF_PROC_LENGTH_PROCESS_NAME];
	RtlZeroMemory(
		procName,
		PTDEF_PROC_LENGTH_PROCESS_NAME * sizeof(WCHAR)
	);

	WCHAR commandLine[PTDEF_PROC_LENGTH_COMMAND_LINE];
	RtlZeroMemory(
		commandLine,
		PTDEF_PROC_LENGTH_COMMAND_LINE * sizeof(WCHAR)
	);

	ULONG bufSize = PTDEF_PROC_LENGTH_COMMAND_LINE * sizeof(WCHAR);

	//
	// If the command line is more than 0, log the command line.
	//
	if (CreateInfo->CommandLine->Length)
	{
		if (CreateInfo->CommandLine->Length <= bufSize)
			bufSize = CreateInfo->CommandLine->Length;

		RtlCopyMemory(
			commandLine,
			CreateInfo->CommandLine->Buffer,
			bufSize
		);
	}

	//
	// Covert ProcessName to WCHAR for ETW logging. 
	//
	bufSize = PTDEF_PROC_LENGTH_PROCESS_NAME;
	if (processName->Length <= bufSize)
		bufSize = processName->Length;

	RtlCopyMemory(
		procName,
		processName->Buffer,
		bufSize
	);

	//
	// If in passive mode, create a log. 
	// If in enforce, block the process and create a log. 
	//
	if (!Globals.Enforced)
	{
		EventWriteProcessCreationBlock_Passive(
			NULL,
			HandleToULong(ProcessId),
			procName,
			HandleToULong(CreateInfo->ParentProcessId),
			commandLine
		);
		goto Cleanup;
	}

	CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;

	EventWriteProcessCreationBlock_Enforced(
		NULL,
		HandleToULong(ProcessId),
		processName->Buffer,
		HandleToULong(CreateInfo->ParentProcessId),
		commandLine
	);


Cleanup:
	//
	// Free allocated memory to prevent memory leaks. 
	//
	if (processName)
		ExFreePoolWithTag(
			processName,
			PTDEF_PROC_TAG_PROCESS_NAME
		);

	if (parentProcessName)
		ExFreePoolWithTag(
			parentProcessName,
			PTDEF_PROC_TAG_PROCESS_NAME
		);

	return;
}
