#include "InsertAPC.h"
#include "myfunction.h"
#include "PageTableSplit.h"
#include "MemLoadDll.h"
#include "dnfheader.h"
#include <ntimage.h>



typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef
VOID
(*PKNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
	);

VOID
normal_routine(
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
)
{	
	PULONG x = (PULONG)NormalContext;
	DbgPrint("pbw: NormalRoutine!~   *NormalContext:%d\n",  *x);
	
};

typedef
VOID
(*PKRUNDOWN_ROUTINE) (
	IN struct _KAPC* Apc
	);

typedef
VOID
(*PKKERNEL_ROUTINE) (
	IN struct _KAPC* Apc,
	IN OUT PKNORMAL_ROUTINE* NormalRoutine,
	IN OUT PVOID* NormalContext,
	IN OUT PVOID* SystemArgument1,
	IN OUT PVOID* SystemArgument2
	);


VOID kernal_routine(
	IN struct _KAPC* Apc,
	IN OUT PKNORMAL_ROUTINE* NormalRoutine,
	IN OUT PVOID* NormalContext,
	IN OUT PVOID* SystemArgument1,
	IN OUT PVOID* SystemArgument2
)
{	
	PULONG x =(PULONG) NormalContext;
	DbgPrint("pbw: KernalRoutine!~    *NormalContext:%s\n",*x);
	ExFreePool(Apc);
};

VOID
KeInitializeApc(
	__out PRKAPC Apc,
	__in PRKTHREAD Thread,
	__in KAPC_ENVIRONMENT Environment,
	__in PKKERNEL_ROUTINE KernelRoutine,
	__in_opt PKRUNDOWN_ROUTINE RundownRoutine,
	__in_opt PKNORMAL_ROUTINE NormalRoutine,
	__in_opt KPROCESSOR_MODE ApcMode,
	__in_opt PVOID NormalContext
);

BOOLEAN
KeAlertThread(
	__inout PKTHREAD Thread,
	__in KPROCESSOR_MODE AlertMode
);

BOOLEAN
KeInsertQueueApc(
	__inout PRKAPC Apc,
	__in_opt PVOID SystemArgument1,
	__in_opt PVOID SystemArgument2,
	__in KPRIORITY Increment
);






NTSTATUS insertUserApc(HANDLE pid)
{
	NTSTATUS status=STATUS_UNSUCCESSFUL;

	PEPROCESS peprocess = NULL;
	status=PsLookupProcessByProcessId(pid,&peprocess);
	if(!NT_SUCCESS(status))
	{
		DbgPrint("pbw: pid��������\n");
		return status;
	}

	PETHREAD pMainThread = GetMainThread(peprocess);
	PETHREAD pThread = NULL;
	PEPROCESS pThreadEProcess = NULL;
	
	for (ULONG i = 4; i < 0x80000; i = i + 4)
	{
		status = PsLookupThreadByThreadId(i,&pThread);
		if (NT_SUCCESS(status))                                    //�ҵ��߳�
		{
			pThreadEProcess = PsGetThreadProcess(pThread);		  //�ҵ��̵߳� ����Ϊpid
			if (peprocess == pThreadEProcess)
			{
				if (pMainThread == pThread)
				{
					DbgPrint("pbw: �ҵ����߳� �����%d \n",i);
					continue;
				}

				ULONG alertable = *((PUCHAR)pThread + 0x74);
				if (alertable >> 4 & 1)
				{
					DbgPrint("pbw: alertableλΪ1����Ҫ����߳�:%p \n", pThread);
				}
				else
				{
					
					DbgPrint("pbw: �ҵ��� �߳�:%p\n", pThread);
					
					break;
				}
			}
			ObDereferenceObject(pThread);
		}
	}
	ObDereferenceObject(peprocess);


	if(!NT_SUCCESS(status))
	{	
		DbgPrint("pbw: δ�ҵ����������߳�\n");
		return status;
	}
	KAPC_STATE apc_state = { 0 };
	
	KeStackAttachProcess(peprocess,&apc_state);

	
	//PUCHAR pDlldata=(PUCHAR)(AllocateMemory(pid, (SIZE_T)sizeof(sysData)));
	//
	///*if (!!MmIsAddressValid(pDlldata))
	//{
	//	KeUnstackDetachProcess(&apc_state);
	//	return status;
	//}*/
	//DbgPrint("pbw: dll��ַ��%p\n", pDlldata);
	//memcpy(pDlldata, sysData, sizeof(sysData));
	//PUCHAR pMyloadlibrary = (PUCHAR)(AllocateMemory(pid, (SIZE_T)sizeof(MemLoadShellcode_x64)));
	//
	///*if(!MmIsAddressValid(pMyloadlibrary))
	//{ 
	//	KeUnstackDetachProcess(&apc_state);
	//	return status;
	//}*/
	//DbgPrint("pbw: ������ַ��%p\n", pMyloadlibrary);
	//memcpy(pMyloadlibrary, MemLoadShellcode_x64, sizeof(MemLoadShellcode_x64));

	//PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pDlldata;
	//PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((PUCHAR)pDlldata + pDos->e_lfanew);

	//SIZE_T uImagesize = pNts->OptionalHeader.SizeOfImage;
	//PUCHAR uDllDataMem = AllocateMemory(pid, uImagesize);
	//


	//pMyloadlibrary[0x50f] = 0x90;
	//pMyloadlibrary[0x510] = 0x48;
	//pMyloadlibrary[0x511] = 0xB8;
	//*(PULONG64)&pMyloadlibrary[0x512] = (PULONG64)uDllDataMem;

	//DbgPrint("pbw: ע��shellcode��ַ�� %p\n", pMyloadlibrary);
	UCHAR MessageBox[] = {
	 	 0x55,                                                      // push rbp    
		 0x48,0x33,0xC9,																//| xor rcx,rcx
		 0x48,0x33,0xD2,													//	 | xor rdx,rdx
		 0x4D,0x33,0xC0,													//| xor r8,r8
		 0x4D,0x33,0xC9,													//| xor r9,r9
		 0x81,0xEC,0x00,0x01,0x00,0x00,												//		| sub esp,100
		 0x48,0xB8,0x89,0x67,0x45,0x23,0x01,0x00,0x00,0x00,										//| mov rax,123456789
		 0xFF,0xD0,															//| call rax
		 0x81,0xC4,0x00,0x01,0x00,0x00,													//	| add esp,100
		 0x5D,                                                      // pop rbp 
		 //0xC3,															//| ret
	};

	*(PULONG64)(&MessageBox[21]) = 0x7FFCE1159AF0;

	PUCHAR pMessageBox = (PUCHAR)(AllocateMemory(pid, (SIZE_T)sizeof(MessageBox)));
	memcpy(pMessageBox,MessageBox,sizeof(MessageBox));
	PKAPC pKapc = ExAllocatePool(NonPagedPool, sizeof(KAPC));
	RtlZeroMemory(pKapc, sizeof(KAPC));
	KeInitializeApc(pKapc,pThread, OriginalApcEnvironment, kernal_routine,0, pMessageBox,UserMode,0);

	*((PUCHAR)pThread + 0x74) |= 0x10;                  //alertable ��1
	
	
	BOOLEAN flag=KeInsertQueueApc(pKapc,0,0,0);
	KeAlertThread(pThread, UserMode);
	

	if (!flag)
	{
		ExFreePool(pKapc);
	}


	//KEVENT kEvent;
	////��ʼ��һ��δ�������ں��¼�
	//KeInitializeEvent(&kEvent, SynchronizationEvent, FALSE);

	////�ȴ�ʱ��ĵ�λ��100���룬��΢��ת���������λ
	////���������ǴӴ˿̵�δ����ĳ��ʱ��
	//LARGE_INTEGER timeout = RtlConvertLongToLargeInteger(-25 * 1000000);

	////�ھ���timeout���̼߳�������
	//KeWaitForSingleObject(&kEvent,
	//	Executive,
	//	KernelMode,
	//	FALSE,
	//	&timeout);
	//


	//memset(pDlldata, 0, 4);

	
	KeUnstackDetachProcess(&apc_state);
	return STATUS_SUCCESS;
}
