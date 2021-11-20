#ifndef __PROCESS_H__
#define __PROCESS_H__

#include "protect.h"

/*************************************************************************
	Process Notification Function Prototypes
*************************************************************************/

void PtOnProcessNotify(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
);

#endif // !__PROCESS_H__
