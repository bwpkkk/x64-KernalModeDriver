#pragma once
#include<ntifs.h> //ntddk.h
#include "myfunction.h"

#include <ntstatus.h>
PVOID regHandle;
HANDLE Pid, realPid, Filehandle;
NTSTATUS IRP_CALL(PDEVICE_OBJECT device, PIRP pirp);

