#pragma warning(disable: 4267 6385 6386 6011 4242 4244)

#include "utility.h"

/*************************************************************************
	Definitions
*************************************************************************/
#define PTDEF_UTIL_TAG_SPLIT 'PSTU'
#define PTDEF_UTIL_TAG_RETAR 'ARTU'

VOID
PtUtilSplitString(
	_In_		PUNICODE_STRING InputString,
	_Out_		PUNICODE_STRING Paths[128],
	_Out_opt_	PULONG			RetSize
)
/*++

Routine Description:

	Takes a W3WProtect config string and splits it on semi colons.

Arguments:

	InputString	- W3WProtect config string that is item deliminated by a
				semi colon.

	RetArray	- An array of the config strings. This should be placed
				witin the `globals` structure.

	RetSize		- The size of retArray.

Returns:

	STATUS_SUCCESS	- Successfully split the string.

--*/
{
	ULONG count = 0; // Counter for how many arrays we have.
	WCHAR* buffer = InputString->Buffer; 
	WCHAR* bufferStart = InputString->Buffer;

	// Zero the memory to ensure that there's no garbage data. 
	//RtlZeroMemory(RetArray, sizeof(InputString->Length));
	//RetArray[*RetSize]->Buffer = InputString->Buffer;

	
	while (buffer < InputString->Buffer + InputString->Length)
	{
		if (*buffer == ';')
		{
			Paths[count] = (PUNICODE_STRING)ExAllocatePoolWithTag(
				PagedPool,
				sizeof(UNICODE_STRING),
				PTDEF_UTIL_TAG_RETAR
			);

			// Update the size of the string based on start of string minus current location.
			Paths[count]->Length = (buffer - bufferStart) *sizeof(WCHAR);
			Paths[count]->MaximumLength = Paths[count]->Length;
			Paths[count]->Buffer = (PWCH)ExAllocatePoolWithTag(
				PagedPool,
				(buffer - bufferStart) * sizeof(WCHAR),
				PTDEF_UTIL_TAG_RETAR
			);

			RtlCopyMemory(
				Paths[count]->Buffer,
				bufferStart,
				Paths[count]->Length
			);			

			count += 1;

			// Add one to the existing buffer to skip the semi-colon if we're not at the 
			// end of the string. . 
			if (buffer + 1 < InputString->Buffer + InputString->Length)
				bufferStart = buffer + 1;
		}
		buffer++;
	}

	*RetSize = count;
	
	return;
}

BOOLEAN
PtContainsUnicodeString
(
	_In_ PCUNICODE_STRING uString,
	_In_ PWSTR cString
)
/*++

Routine Description:

	Takes a UNICODE_STRING and sees if the PWSTR is within.

Arguments:

	uString - UNICODE_STRING to compare against.

	cString - String to comapare.

Returns:

	TRUE	- String was found.

	FALSE	- String wasn't found.

--*/
{
	ULONG cLen = wcslen(cString);
	PWCHAR buffer = uString->Buffer;
	PWCHAR bufferEnd = uString->Buffer + (uString->Length / sizeof(WCHAR));

	while (buffer < bufferEnd)
	{
		if (*buffer == *cString)
		{
			for (ULONG i = 0; i < cLen; i++)
			{
				if (*(buffer + i) != *(cString + i))
					goto Increment;
			}
			return TRUE;
		}

		// Increment lets out break out of multiple loops. 
	Increment:
		buffer++;
	}

	return FALSE;
}