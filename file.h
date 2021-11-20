#ifndef __FILE_H__
#define __FILE_H__

#include "protect.h"
#include "process.h"

/*************************************************************************
	Mini-Filter	Function Prototypes
*************************************************************************/

FLT_PREOP_CALLBACK_STATUS
PtPreCreateOp(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
PtPreWriteOp(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

#endif // !__FILE_H__

