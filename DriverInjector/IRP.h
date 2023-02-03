#pragma once
#include<ntifs.h> //ntddk.h
#include "myfunction.h"

#include <ntstatus.h>
HANDLE Pid;
NTSTATUS IRP_CALL(PDEVICE_OBJECT device, PIRP pirp);
