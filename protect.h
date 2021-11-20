#ifndef __PROTECT_H__
#define __PROTECT_H__

#ifndef RTL_USE_AVL_TABLES
#define RTL_USE_AVL_TABLES
#endif // !RTL_USE_AVL_TABLES


#include <fltKernel.h>
#include <ntstrsafe.h>
#include <minwindef.h>
#include <wdf.h>

#include "ptEtw.h"
#include "registry.h"
#include "process.h"
#include "file.h"

/*************************************************************************
    Globals
*************************************************************************/

typedef struct _PROTECT_GLOBAL_DATA
{
    //
    // Driver object, used for writing event logs.
    //
    PDRIVER_OBJECT DriverObject;

    //
    // Reg path, used to monitor for config updates.
    //
    PUNICODE_STRING RegistryPath;

    //
    // WDF Driver Object, user for registry management.
    //
    WDFDRIVER WdfDriver;
    

    //
    // Keep track of how many events we've recorded. 
    //
    LONGLONG EventIdCounter;

    //
    // Mini Filter filter. 
    //
    PFLT_FILTER Filter;

    //
    // Registry cookie to track out RegNotify
    //
    LARGE_INTEGER RegCookie;

    //
    // Reg Altitude
    //
    ULONG RegAlt;

    //
    // Config Whitelisted Directory
    //
    PUNICODE_STRING ConfigWhiteListedDirectory[128];
    ULONG ConfigDirSize;
    
    //
    // Config Whitelisted Processes
    //
    PUNICODE_STRING ConfigWhitelistedProcesses[128];
    ULONG ConfigProcessSize;

    //
    // Config Whitelisted Registry
    //
    PUNICODE_STRING ConfigWhitelistedRegistry[128];
    ULONG ConfigRegSize;

    // 
    // Config Enforced
    // Are we enforcing blocking processes?
    //
    BOOLEAN Enforced;
} PROTECT_GLOBAL_DATA, *PPROTECT_GLOBAL_DATA;

PROTECT_GLOBAL_DATA Globals;

/*************************************************************************
    Driver Registration Function Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

VOID
PtUnload(
    _In_ PDRIVER_OBJECT DriverObject
);

NTSTATUS
PtMFUnload(
    _Unreferenced_parameter_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
InitGlobal(
    _In_ UNICODE_STRING RegistryPath
);

/*************************************************************************
    WinApi Function Prototypes
*************************************************************************/

NTSTATUS
ZwQueryInformationProcess(
    _In_        HANDLE              ProcessHandle,
    _In_        PROCESSINFOCLASS    ProcessInformationClass,
    _Out_       PVOID               ProcessInformation,
    _In_        ULONG               ProcessInformationLength,
    _Out_opt_   PULONG              ReturnLength
);


#endif // !__PROTECT_H__

