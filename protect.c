/*++

Module Name:

	protect.c

Abstract:

	The base of W3WProtect. Contains the setup and unloading for W3WProtect.

--*/

#pragma warning(disable: 4152 6001 6387 6011)

#include "protect.h"

/*++

ToDo
	- Fix up the Mini-Filter, read/write.
		Essentially the same, just need either a way to tell the difference
		rather than seperate them out into functions.

	- Functionize code reuse.
		- Unicode string pool allocation and zero-ing.
		- PtGetProcessName

	- Add more logging
		- Load/Unload. 

--*/

/*************************************************************************
	Definitions
*************************************************************************/

// Acronym in reverse due to little endian. 

#define PTDEF_TAG_REGALT		'ARDP'
#define PTDEF_TAG_REGKEY		'KRDP'


EVT_WDF_DRIVER_DEVICE_ADD PtWdfDriverDeviceAdd;

/*************************************************************************
	Mini-Filter Registration Functions
*************************************************************************/

CONST
FLT_OPERATION_REGISTRATION
Callbacks[] =
{
	{
		IRP_MJ_CREATE,			// Major Functions
		0,						// Flags
		PtPreCreateOp,			// Pre Operation
		NULL					// Post Operation
	},
	{
		IRP_MJ_WRITE,			// Major Function
		0,						// Flags
		PtPreWriteOp,			// Pre Operation
		NULL					// Post Operation
	},
	{IRP_MJ_OPERATION_END}
};


//
// Context registration construct for the FLT_REGISTRATION
// 
// Currently unused. Will need to reference avscan.c to see
// if I want to use it.
//
extern const FLT_CONTEXT_REGISTRATION ContextRegistration[];

const FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),		// Size
	FLT_REGISTRATION_VERSION,		// Version
	0,								// Flags
	NULL,							// Context Registration,
	Callbacks,						// Operation Callbacks
	PtMFUnload,						// MiniFilterUnload
	NULL,							// InstanceSetup
	NULL,							// InstanceQueryTeardown
	NULL,							// InstanceTeardownStart
	NULL,							// InstanceTeardownComplete

	NULL,							// GenerateFileName
	NULL,							// NormalizeNameComponentCallback
	NULL,							// NormalizeContextCleanupCallback
	NULL,							// TransactionNotificationCallback
	NULL,							// NormalizeNameComponentExCallback
	NULL							// SectionNotificationCallback
};

/*************************************************************************
	Driver Setup Functions
*************************************************************************/

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	//
	// Register the ETW Provider
	//
	EventRegisterW3WProtect();

	NTSTATUS status;

	Globals.DriverObject = DriverObject;

	/*
	Globals.RegistryPath = ExAllocatePoolWithTag(
		PagedPool,
		RegistryPath->Length,
		PTDEF_TAG_REGKEY
	);
	RtlZeroMemory(Globals.RegistryPath, RegistryPath->Length);
	RtlCopyUnicodeString(Globals.RegistryPath, RegistryPath); // Why does this not work???
	*/
	RtlInitUnicodeString(
		Globals.RegistryPath,
		L"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\w3wprotect"
	);
	//
	// Setup the Registry notify.
	// Do this before configuration generation, in case somehow they
	// try to change a value while we're starting up. 
	// 
	// ToDo - Setup a do/while to handle changing altitude if there's
	// a conflict. 
	//
	 
	UNICODE_STRING regAlt = RTL_CONSTANT_STRING(L"494477.123");
	status = CmRegisterCallbackEx(
		PtRegNotify,
		&regAlt,
		DriverObject,
		NULL,
		&Globals.RegCookie,
		NULL
	);
	if (!NT_SUCCESS(status))
		return status;


	status = PtUpdateConfig();
	if (!NT_SUCCESS(status))
		return status;




	//
	// Setup the mini-filter.
	//
	status = FltRegisterFilter(
		DriverObject,
		&FilterRegistration,
		&Globals.Filter
	);
	if (!NT_SUCCESS(status))
		return status;

	status = FltStartFiltering(Globals.Filter);
	if (!NT_SUCCESS(status))
		return status;

	//
	// Setup Process Notifier.
	//
	status = PsSetCreateProcessNotifyRoutineEx(
		PtOnProcessNotify,		// Function to call
		FALSE					// Do not remove. 
	);
	if (!NT_SUCCESS(status))
		return status;

	EventWriteW3WProtect_Load(NULL);

	return status;
}

VOID
PtUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);

	//
	// Unregister process notify.
	//
	PsSetCreateProcessNotifyRoutineEx(
		PtOnProcessNotify,		// Function to remove.
		TRUE					// Remove is TRUE. 
	);

	//
	// Unregister Configuration Register callback. 
	//
	CmUnRegisterCallback(Globals.RegCookie);

	ExFreePoolWithTag(Globals.RegistryPath, PTDEF_TAG_REGKEY);

	//
	// Unregister ETW
	//
	EventWriteW3WProtect_Unload(NULL);
	EventUnregisterW3WProtect();
}

NTSTATUS
PtMFUnload(
	_Unreferenced_parameter_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER(Flags);

	FltUnregisterFilter(Globals.Filter);  // This will typically trigger instance tear down.
	Globals.Filter = NULL;

	return STATUS_SUCCESS;
}