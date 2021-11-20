/*++

Module Name:

	registry.h

Abstract:

	Header for W3WProtects registry functionality. This includes reading the 
	config from memory, converting the registry value into a string array. 

Environment:

	Kernel

--*/

#ifndef __PT_REGISTRY_H__
#define __PT_REGISTRY_H__

#include "protect.h"
#include "utility.h"

/*************************************************************************
	Registry Config Update Function Prototypes
*************************************************************************/

NTSTATUS
PtUpdateConfig();

NTSTATUS
PtRegQueryValue(
	_In_  HANDLE Key,
	_In_  PCWSTR ValueName,
	_Out_ BYTE* Buffer,
	_Out_ PULONG ReturnedSize
);

/*************************************************************************
	Registry Notification Function Prototypes
*************************************************************************/

NTSTATUS PtRegNotify(
	_In_	PVOID CallbackContext,
	_In_	PVOID Argument1,
	_Inout_ PVOID Argument2
);

#endif // !__PT_REGISTRY_H__
