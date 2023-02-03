#pragma once
#include<ntifs.h>



ULONG64 GetPML4(ULONG64 linearAddress);

PVOID AllocateMemory(HANDLE pid, SIZE_T size);