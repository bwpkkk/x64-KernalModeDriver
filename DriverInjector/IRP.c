#include "IRP.h"
#include "PageTableSplit.h"
#include "MemLoadDll.h"
#include "dnfheader.h"
#include <ntimage.h>
#define PROCESSID CTL_CODE(FILE_DEVICE_UNKNOWN,  0x803, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试


void ThreadHijack(PIRP pirp, PDRIVER_OBJECT driverobj)

{
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pirp);
	irpStack;
	int* Buffer = (int*)pirp->AssociatedIrp.SystemBuffer;
	
	
	//DbgPrint("pbw:* Buffer=%d，行号：%d\n",*(Buffer),__LINE__);
	Pid = (HANDLE)*Buffer;
	
	PWCH tname = L"ntoskrnl.exe";
	PULONG size = 0;
	PVOID baseAddr = FindModule(driverobj, tname, &size);
	
	//DbgPrint("NTOSKRNL.exe 地址=%p\n", baseAddr);

	UCHAR shellcode[31] = { 0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x6C,0x24,0x10,0x48,0x89,0x74,0x24,0x18,
		0x57,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x30,0x48,0x8B,0xF9,0x44,0x0F,0x20,0xC3 };   //WIN10X64

	PVOID dwreturn = FindFun(baseAddr, size, shellcode, 31);
	PVOID dwreturn2, dwreturn3;
	//DbgPrint("Kesuspendthread 地址=%p\n", dwreturn);               

	



	PEPROCESS peprocess = { 0 };

	NTSTATUS status = PsLookupProcessByProcessId(Pid, &peprocess);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("pbw: PsLookupProcessByProcessId 失败\n");
		return;
	}
	PETHREAD temp = GetMainThread(peprocess);
	

	status = KeSuspendThread(temp, dwreturn);                                // SUSPEND THREAD
	SuspendA11Thread(dwreturn);

	ULONG64 initstack = *(PULONG64)((PCHAR)temp + 0x28);
	PKTRAP_FRAME trapframe =(PKTRAP_FRAME)(initstack - sizeof(KTRAP_FRAME));    // GET RIP
	DbgPrint("pbw: trapframe->rip: %p\n", trapframe->Rip);
	

	KAPC_STATE kapc_state= { 0 };
	KeStackAttachProcess(peprocess,&kapc_state);


	SIZE_T zwSize = 2*PAGE_SIZE;
	PVOID zwBase=0;
	//ZwAllocateVirtualMemory(NtCurrentProcess(),&zwBase,0,&zwSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	zwBase=AllocateMemory(Pid,zwSize);
	
	PCHAR ms = (PCHAR)zwBase + PAGE_SIZE;				 //ALLOCATE MEMORY
	DbgPrint("pbw: zwBase地址： %p\nms地址： %p\n", zwBase,ms);



	UCHAR myshellcode[] = {
			 0x55,                                                      // push rbp                                |
			 0x48,0x81,0xEC,0x00,0x01,0x00,0x00,                        // sub rsp,100                             |
			 0x50,                                                      // push rax                                |
			 0x48,0xB8,0x89,0x67,0x45,0x23,0x01,0x00,0x00,0x00,         // mov rax,123456789                       |
			 0xFF,0xD0,                                                 // call rax                                |
			 0x58,                                                      // pop rax                                 |
			 0x48,0x81,0xC4,0x00,0x01,0x00,0x00,                         // add rsp,100                             |
			 0x5D,                                                      // pop rbp                                 |
			 0xFF,0x25,0x00,0x00,0x00,0x00,                              // jmp qword ptr ds:[7FFC72CCAD18]}；
			 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};


	*(PULONG64)(&myshellcode[11]) = ms;
	*(PULONG64)(&myshellcode[36]) = trapframe->Rip;
	
	char* uMem = AllocateMemory(Pid,sizeof(sysData));
	char* uLoadMem = AllocateMemory(Pid, sizeof(MemLoadShellcode_x64));

	memcpy(uMem, sysData, sizeof(sysData));
	memcpy(uLoadMem, MemLoadShellcode_x64, sizeof(MemLoadShellcode_x64));
	DbgPrint("pbw: dnfheader地址： %p\n x64shellcode地址： %p\n", uMem, uLoadMem);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)uMem;
	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(uMem + pDos->e_lfanew);
	SIZE_T uImagesize = pNts->OptionalHeader.SizeOfImage;

	PUCHAR uDllDataMem = AllocateMemory(Pid,uImagesize);
	uLoadMem[0x50f] = 0x90;
	uLoadMem[0x510] = 0x48;
	uLoadMem[0x511] = 0xB8;
	*(PULONG64)&uLoadMem[0x512] = (ULONG64)uDllDataMem;

	DbgPrint("pbw: 替换virtualalloc地址： %p\n", uDllDataMem);
                              


	
	UCHAR Myloadlibrary[] = {

			 0x48,0xB9,0x89,0x67,0x45,0x23,0x01,0x00,0x00,0x00,				// mov rcx,123456789
			0x48,0xB8,0x44,0x33,0x22,0x22,0x11,0x11,0x00,0x00              // mov rax,7FF8C5D1A160
			,0x81,0xEC,0x00,0x01,0x00,0x00                                   //sub esp,100
			,0xFF,0xD0,		                                                   // call rax
			0x81,0xC4,0x00,0x01,0x00,0x00                                   //add esp,100
			,0xC3                                                           // ret
	};
	*(PULONG64)(&Myloadlibrary[2]) = uMem;
	*(PULONG64)(&Myloadlibrary[12]) = uLoadMem;

	//
	//UCHAR MessageBox[] = {
	// 	 0x55,                                                      // push rbp    
	//	 0x48,0x33,0xC9,																//| xor rcx,rcx
	//	 0x48,0x33,0xD2,													//	 | xor rdx,rdx
	//	 0x4D,0x33,0xC0,													//| xor r8,r8
	//	 0x4D,0x33,0xC9,													//| xor r9,r9
	//	 0x81,0xEC,0x00,0x01,0x00,0x00,												//		| sub esp,100
	//	 0x48,0xB8,0x89,0x67,0x45,0x23,0x01,0x00,0x00,0x00,										//| mov rax,123456789
	//	 0xFF,0xD0,															//| call rax
	//	 0x81,0xC4,0x00,0x01,0x00,0x00,													//	| add esp,100
	//	 0x5D,                                                      // pop rbp 
	//	 0xC3,															//| ret
	//};

	//*(PULONG64)(&MessageBox[20]) = 0x7FFDB533A160;



	memcpy(zwBase,myshellcode,sizeof(myshellcode));
	memcpy(ms, Myloadlibrary, sizeof(Myloadlibrary));

	trapframe->Rip = zwBase;
	

	UCHAR shellcode3[] = {
	0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x6C,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x57,0x41,0x56,0x41,0x57,
	0x48,0x83,0xEC,0x30,0x8B,0xEA,0x48,0x8B,0xD9,0x44,0x0F,0x20,0xC7,0xB9 };


	dwreturn3 = FindFun(baseAddr, size, shellcode3, 34);

	
	status = KeResumeThreadWin11(temp, dwreturn3);
	ResumeAllThread(dwreturn3);
	

	//KEVENT kEvent;
	////初始化一个未激发的内核事件
	//KeInitializeEvent(&kEvent, SynchronizationEvent, FALSE);

	////等待时间的单位是100纳秒，将微秒转换成这个单位
	////负数代表是从此刻到未来的某个时刻
	//LARGE_INTEGER timeout = RtlConvertLongToLargeInteger(-20 * 1000000);

	////在经过timeout后，线程继续运行
	//KeWaitForSingleObject(&kEvent,
	//	Executive,
	//	KernelMode,
	//	FALSE,
	//	&timeout);
	//memset(uMem,0,4);
	
	//
	//status=ZwFreeVirtualMemory(NtCurrentProcess(), &zwBase, &zwSize, MEM_RELEASE);
	//if (!NT_SUCCESS(status))
	//{
	//	DbgPrint("pbw:释放内存失败\n");
	//}		
	
	KeUnstackDetachProcess(&kapc_state);
	//DbgPrint(("pbw: RegistryPath=%s\n", RegistryPath->Buffer)); //多字节字符集
	


	pirp->IoStatus.Status = STATUS_SUCCESS;
	pirp->IoStatus.Information = sizeof(int);//返回给DeviceIoControl中的 倒数第二个参数lpBytesReturned
	IoCompleteRequest(pirp, IO_NO_INCREMENT);//调用方已完成所有I/O请求处理操作 并且不增加优先级 
	DbgPrint("pbw:离开派遣函数\n");

}



NTSTATUS IRP_CALL(PDEVICE_OBJECT device, PIRP pirp)
{	
	device;

	DbgPrint("pbw:进入派遣函数");
	PIO_STACK_LOCATION irpStackL;
	irpStackL = IoGetCurrentIrpStackLocation(pirp);
	switch (irpStackL->MajorFunction)
	{
		case IRP_MJ_DEVICE_CONTROL:
		{
			UINT32 code = irpStackL->Parameters.DeviceIoControl.IoControlCode;
			if (code== PROCESSID)
			{	
				DbgPrint("pbw: IOCTL: PROCESS ID: %d\n", code);
				ThreadHijack(pirp, device->DriverObject);
				return STATUS_SUCCESS;
			}
			break; 
		}
		

		case IRP_MJ_CREATE: //CreateFile
		{

			DbgPrint("pbw:用户层调用了 CreateFile\n");
			
			break;
		}
		case IRP_MJ_CLOSE: //CloseHandle
		{

			DbgPrint("pbw:用户层调用了 CloseHandle\n");
			
			break;
		}
		
	}



	pirp->IoStatus.Status = STATUS_SUCCESS;
	pirp->IoStatus.Information = 4;//返回给DeviceIoControl中的 倒数第二个参数lpBytesReturned
	IoCompleteRequest(pirp, IO_NO_INCREMENT);//调用方已完成所有I/O请求处理操作 并且不增加优先级 
	DbgPrint("pbw:离开派遣函数");
	return STATUS_SUCCESS;  //0 返回成功
} 