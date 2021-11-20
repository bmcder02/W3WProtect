/*++

Module Name:

	registry.c

Abstract:

	Contains the registry functionality for W3WProtect. This includes reading 
	the config from memory, swapping the string array into a single string and
	converting the registry value into a string array.

Environment:

	Kernel

--*/

#pragma warning(disable: 6387 6011 26451 4305 4242 4244)

#include "registry.h"

#define PTDEF_REG_TAG_VALUEINFO 'IVTR'
#define PTDEF_REG_TAG_BUFFSIZE  'SBTR'
#define PTDEF_REG_TAG_PROCESS_NAME	'NPDP'
#define PTDEF_REG_LENGTH_PROCESS_NAME 500

/*************************************************************************
	Registry Config Update Functions
*************************************************************************/

NTSTATUS
PtUpdateConfig()
/*++

Routine Description:

	Takes the registry path to the W3WProtect service, opens the default config
	key and enumerates through the required valies. 

	Directly update the Global config. 

Arguments

	RegistryPath	- Path to the W3WProtect Service Registry keys. 

Returns:

	STATUS_SUCCESS	- Successfully updated global config. 

--*/
{
	NTSTATUS status;
	HANDLE hConfig = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;

	BYTE DirBuffer[1024];
	ULONG DirSize = 0;
	PUNICODE_STRING sDir = NULL;

	BYTE ProcBuffer[1024];
	ULONG ProcSize = 0;
	PUNICODE_STRING sProc = NULL;
	
	BYTE RegBuffer[1024];
	ULONG RegSize = 0;
	PUNICODE_STRING sReg = NULL;

	BYTE EnforcedBuffer[0x10];
	ULONG EnforcedSize = 0;


	InitializeObjectAttributes(
		&ObjectAttributes,
		Globals.RegistryPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);

	status = ZwOpenKey(
		&hConfig,
		KEY_READ,
		&ObjectAttributes
	);

	if (!NT_SUCCESS(status))
		return status;

	//
	// Setup Whitelisted directories.
	//

	status = PtRegQueryValue(
		hConfig,
		L"WhiteListedDirectories",
		DirBuffer,
		&DirSize
	);
	if (!NT_SUCCESS(status))
		return status;

	PWSTR cDir = (PWSTR)DirBuffer;
	sDir = ExAllocatePoolWithTag(
		PagedPool,
		DirSize,
		PTDEF_REG_TAG_BUFFSIZE
	);

	sDir->Length = DirSize;
	sDir->MaximumLength = DirSize;
	sDir->Buffer = cDir;
	
	PtUtilSplitString(
		sDir,
		Globals.ConfigWhiteListedDirectory,
		&Globals.ConfigDirSize
	);


	//
	// Setup Whitelisted Processes.
	//
	status = PtRegQueryValue(
		hConfig,
		L"WhiteListedProcesses",
		ProcBuffer,
		&ProcSize
	);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	PWSTR cProc = (PWSTR)ProcBuffer;
	sProc = ExAllocatePoolWithTag(
		PagedPool,
		ProcSize,
		PTDEF_REG_TAG_BUFFSIZE
	);

	sProc->Length = ProcSize;
	sProc->MaximumLength = ProcSize;
	sProc->Buffer = cProc;

	PtUtilSplitString(
		sProc,
		Globals.ConfigWhitelistedProcesses,
		&Globals.ConfigProcessSize
	);

	//
	// Setup Whitelisted Registry.
	//
	status = PtRegQueryValue(
		hConfig,
		L"WhiteListedRegistry",
		RegBuffer,
		&RegSize
	);	
	if (!NT_SUCCESS(status))
		goto Cleanup;

	PWSTR cReg = (PWSTR)RegBuffer;
	sReg = ExAllocatePoolWithTag(
		PagedPool,
		RegSize,
		PTDEF_REG_TAG_BUFFSIZE
	);

	sReg->Length = RegSize;
	sReg->MaximumLength = RegSize;
	sReg->Buffer = cReg;

	PtUtilSplitString(
		sReg,
		Globals.ConfigWhitelistedRegistry,
		&Globals.ConfigRegSize
	);

	//
	// Setup Enforcement
	// Does a blanket, if not 0x1 set to passive.
	//
	status = PtRegQueryValue(
		hConfig,
		L"Enforced",
		EnforcedBuffer,
		&EnforcedSize
	);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	if (EnforcedBuffer[0] == 0x1)
		Globals.Enforced = TRUE;
	else
		Globals.Enforced = FALSE;

	//
	// Cleanup
	//
Cleanup:

	//RtlFreeUnicodeString(sDir);
	//RtlFreeUnicodeString(sProc);
	//RtlFreeUnicodeString(sReg);	
	ZwClose(hConfig);

	if (NT_SUCCESS(status))
		EventWriteW3WProtect_Config_Updated(NULL);
	else
		EventWriteW3WProtect_Config_FailedToLoad(NULL);

	return status;
}

NTSTATUS
PtRegQueryValue(
	_In_  HANDLE Key,
	_In_  PCWSTR ValueName,
	_Out_ BYTE	 Buffer[],
	_Out_ PULONG ReturnedSize
)
/*++

Routine Description:

	Queries a registry value and returns a BYTE buffer.

Arguments

	Key			- A handle to the key which contains the value. 

	ValueName	- The name of the value to read.

	Buffer		- The contents of the value. 

	ReturnedSize - Size of the buffer.

Returns:

	STATUS_SUCCESS	- Successfully updated global config.

	STATUS_OBJECT_NOT_FOUND - Could not find the value.

	Result from ZwQueryValueKey;

--*/
{
	NTSTATUS status;
	UNICODE_STRING valueName;
	*ReturnedSize = 0;
	RtlInitUnicodeString(&valueName, ValueName);

	status = ZwQueryValueKey(
		Key,
		&valueName,
		KeyValuePartialInformation,
		NULL,
		0,
		ReturnedSize
	);
	if (NT_SUCCESS(status) == STATUS_OBJECT_NAME_NOT_FOUND ||
		ReturnedSize == 0)
	{
		//RtlFreeUnicodeString(&valueName); // Work out how to do this safetly.
		return status;
	}
		

	PKEY_VALUE_PARTIAL_INFORMATION pValue = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(
		PagedPool,
		*ReturnedSize,
		PTDEF_REG_TAG_VALUEINFO
	);

	status = ZwQueryValueKey(
		Key,
		&valueName,
		KeyValuePartialInformation,
		pValue,
		*ReturnedSize,
		ReturnedSize
	);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	RtlCopyMemory(
		Buffer,
		pValue->Data,
		pValue->DataLength
	);

Cleanup:
	//RtlFreeUnicodeString(&valueName); // Work out how to do this safetly.

	if (pValue)
		ExFreePoolWithTag(pValue, PTDEF_REG_TAG_VALUEINFO);

	return status;
}

/*************************************************************************
	Registry Notification Functions
*************************************************************************/

NTSTATUS PtRegNotify(
	_In_	PVOID CallbackContext,
	_In_	PVOID Argument1,
	_Inout_ PVOID Argument2
)
/*++

Routime Description:

	Alerts on registery requests.

	If there is a write request to our configuration path, check to see
	if it is a valid value. If so, update our config.

	If there is a write from W3WP, do a check to see if it is allowed.

Arguments:

	CallbackContext		- The context record requested when we setup the
						notify routine.

	Argument1			- The REG_NOTIFY_CLASS telling us the type of
						action that it is.

	Argument2			- The information specific to the operation.

Returns:

	STATUS_SUCCESS			- The modification is allowed.

	STATUS_ACCESS_DENIED	- The request did not meet a requirement.

--*/
{
	UNREFERENCED_PARAMETER(CallbackContext);
	NTSTATUS status;
	PREG_POST_OPERATION_INFORMATION args;
	PUNICODE_STRING keyName = NULL;
	PUNICODE_STRING processName = NULL;
	ULONG retSize;

	switch ((REG_NOTIFY_CLASS)(ULONG_PTR)Argument1)
	{
		//
		//  Check if it's a config change. 
		//
	case RegNtPostSetValueKey:
		args = (PREG_POST_OPERATION_INFORMATION)Argument2;

		//
		// Check to see if the update was successful.
		// If not, ignore it. 
		//
		if (!NT_SUCCESS(args->Status))
			break;

		//
		// Get the name of the modified key.
		//
		status = CmCallbackGetKeyObjectIDEx(
			&Globals.RegCookie,
			args->Object,
			NULL,
			&keyName,
			0
		);
		if (!NT_SUCCESS(status))
			break;

		if (!PtContainsUnicodeString(keyName, L"w3wprotect"))
		{
			CmCallbackReleaseKeyObjectIDEx(keyName);
			break;
		}
		//
		// To Do - Just update the relevant key
		// rather then everything.
		//
		PtUpdateConfig();

		CmCallbackReleaseKeyObjectIDEx(keyName);

		break;

		// Check if it's a W3WP change.
	case RegNtPreSetValueKey:

		processName = (UNICODE_STRING*)ExAllocatePoolWithTag(
			PagedPool,
			PTDEF_REG_LENGTH_PROCESS_NAME,
			PTDEF_REG_TAG_PROCESS_NAME
		);
		if (!processName)
			return STATUS_SUCCESS;
		RtlZeroMemory(processName, PTDEF_REG_LENGTH_PROCESS_NAME);

		status = ZwQueryInformationProcess(
			NtCurrentProcess(),					// Process Handle
			ProcessImageFileName,				// PROCESSINFOCLASS
			processName,						// Buffer
			PTDEF_REG_LENGTH_PROCESS_NAME,		// SizeOfBuffer
			&retSize							// Return size. 
		);
		if (!NT_SUCCESS(status) ||
			retSize == 0 ||
			processName->Length == 0)
			return STATUS_SUCCESS;


		//
		// If the process isn't w3wp,
		// leave it alone.
		//

		if (!PtContainsUnicodeString(processName, L"w3wp"))
			return STATUS_SUCCESS;


		args = (PREG_POST_OPERATION_INFORMATION)Argument2;

		//
		// Get the name of the modified key.
		//
		status = CmCallbackGetKeyObjectIDEx(
			&Globals.RegCookie,
			args->Object,
			NULL,
			&keyName,
			0
		);
		if (!NT_SUCCESS(status))
			break;

		for (ULONG i = 0; i < Globals.ConfigRegSize; i++)
		{
			if (wcsstr(keyName->Buffer, Globals.ConfigWhitelistedRegistry[i]->Buffer) != NULL)
			{
				if (!Globals.Enforced)
				{
					EventWriteRegSetValueBlock_Passive(NULL, keyName->Buffer);
					break;
				}

				EventWriteRegSetValueBlock_Enforced(NULL, keyName->Buffer);
				//RtlFreeUnicodeString(keyName);
				return STATUS_ACCESS_DENIED;
			}
		}

		break;
	}
	
	//if (keyName != NULL)
		//RtlFreeUnicodeString(keyName);

	return STATUS_SUCCESS;
}
