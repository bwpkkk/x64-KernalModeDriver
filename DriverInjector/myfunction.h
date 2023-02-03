#pragma once
#include<ntifs.h>

PETHREAD GetMainThread(PEPROCESS ptrProcess);


NTSTATUS KeResumeThreadWin11(PETHREAD Thread, PVOID addr);
NTSTATUS KeResumeThread(PETHREAD Thread, PVOID addr);   //WIN10  X64 
NTSTATUS KeSuspendThread(PETHREAD Thread, PVOID addr);   
PVOID FindFun(PVOID pSearchBeginAddr, ULONG ulSearchLength, PUCHAR pSpecialCode, ULONG ulSpecialCodeLength);

PVOID FindModule(PDRIVER_OBJECT pDriverObject, PWCHAR moudName, PULONG pSize);

PVOID SuspendA11Thread(PVOID Kefunc);

PVOID ResumeAllThread(PVOID Keresumefunc);
