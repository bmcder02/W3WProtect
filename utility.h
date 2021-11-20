/*++

Module Name:

	utility.h

Abstract:

	Utility header for w3wprotect. 
	
	Contains general functions that provide "ease of life" functionality. 

Environment:

	Kernel

--*/


#ifndef __PT_UTILITY_H__
#define __PT_UTILITY_H__

#include "protect.h"

VOID
PtUtilSplitString(
	_In_		PUNICODE_STRING InputString,
	_Out_		PUNICODE_STRING RetArray[128],
	_Out_opt_	PULONG			RetSize
);

BOOLEAN
PtContainsUnicodeString(
	_In_ PCUNICODE_STRING uString,
	_In_ PWSTR cString
);

#endif // !__PT_UTILITY_H__
