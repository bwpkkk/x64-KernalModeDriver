#include "IRP.h"

#include "PageTableSplit.h"

#include <ntimage.h>
#define PROCESSID CTL_CODE(FILE_DEVICE_UNKNOWN,  0x805, METHOD_BUFFERED,FILE_ANY_ACCESS) 
#define REALPROCESSID CTL_CODE(FILE_DEVICE_UNKNOWN,  0x806, METHOD_BUFFERED,FILE_ANY_ACCESS) 
#define FILETOKERNEL CTL_CODE(FILE_DEVICE_UNKNOWN,  0x800, METHOD_BUFFERED,FILE_ANY_ACCESS) 


signed __int64 __fastcall ExpLookupHandleTableEntry(unsigned int* a1, __int64 a2)
{
	unsigned __int64 v2; // rdx
	__int64 v3; // r8
	signed __int64 v4; // rax
	__int64 v5; // rax

	v2 = a2 & 0xFFFFFFFFFFFFFFFCui64;
	if (v2 >= *a1)
		return 0i64;
	v3 = *((ULONG64*)a1 + 1);
	v4 = *((ULONG64*)a1 + 1) & 3i64;
	if (v4 == 1)
	{
		v5 = *(ULONG64*)(v3 + 8 * (v2 >> 10) - 1);
		return v5 + 4 * (v2 & 0x3FF);
	}
	if (v4)
	{
		v5 = *(ULONG64*)(*(ULONG64*)(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF));
		return v5 + 4 * (v2 & 0x3FF);
	}
	return v3 + 4 * v2;
}

void ProtectProcess(PIRP pirp, PDRIVER_OBJECT driverobj)

{
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pirp);
	irpStack;
	int* Buffer = (int*)pirp->AssociatedIrp.SystemBuffer;
	
	
	DbgPrint("pbw:* Buffer=%d，行号：%d\n",*(Buffer),__LINE__);
	 Pid = (HANDLE)*Buffer;
	
	PWCH tname = L"ntoskrnl.exe";
	PULONG size = 0;
	PVOID baseAddr = FindModule(driverobj, tname, &size);
	
	DbgPrint("NTOSKRNL.exe 地址=%p\n", baseAddr);

	UCHAR shellcode[43] = { 0x48,0x89,	0x5C,0x24,0x08,0x48,
								0x89,0x74,
								0x24,0x10,
								0x48,0x89,
								0x7C,0x24,
								0x18,0x41,
								0x56,0x48,0x83,0xEC,
								0x20,0x65,0x48,0x8B,
								0x3C,0x25,0x88,0x01,0x00,0x00,
								0x4C,0x8B,
								0xF2,0xB2,
								0x03,0x66,
								0xFF,0x8F,
								0xE6,0x01,
								0x00,0x00,
								0x90 };   //WIN10X64 PsLookupProcessByProcessId

	PVOID dwreturn = FindFun(baseAddr, size, shellcode, 43);
	
	if (!dwreturn)
	{
		DbgPrint("pbw:未能获取函数 PsLookupProcessByProcessId\n");
		return;
	}

		PUCHAR calladdr = ((PUCHAR)dwreturn + 44);
		
		ULONG64 CallReferenceCidEntry = (ULONG64)*(PULONG32)calladdr;
		ULONG64 nextInstruction = (ULONG64)((PUCHAR)dwreturn + 48);
		
		PUCHAR ReferenceCidEntry = (PUCHAR)(CallReferenceCidEntry + nextInstruction);
		ReferenceCidEntry -= 0x100000000;
		//DbgPrint("dwreturn  地址：%p\ncalladdr 地址：%p\nCallReferenceCidEntry  地址：%p\nnextInstruction   地址：%p\n ReferenceCidEntry   地址：%p\n", dwreturn, calladdr,CallReferenceCidEntry, nextInstruction, ReferenceCidEntry);
		
		ReferenceCidEntry += 23;

		DbgPrint(" ReferenceCidEntry %p\n", ReferenceCidEntry);
		ULONG32 PsCidTableoffset = *(ULONG32*)ReferenceCidEntry;
	
		PULONG64 PsCidTableAddr = (PULONG64)(ReferenceCidEntry + 4 + PsCidTableoffset);
		ULONG64 PsCidTable = *(PULONG64*)PsCidTableAddr;

		
		DbgPrint("pbw:PsCidTableAddr  地址：%p\nPsCidTable \n", PsCidTableAddr, PsCidTable );
		ULONG64 HandleTableEntry = ExpLookupHandleTableEntry(PsCidTable, (__int64)Pid);
			DbgPrint("tableentry: 地址：%p \n", HandleTableEntry);
		
		PEPROCESS peprocess = 0;
		NTSTATUS status;
		status=PsLookupProcessByProcessId(Pid,&peprocess);
		
	
	
		*(PULONG64)HandleTableEntry = 0;
		
		*(PULONG64)((PUCHAR)peprocess + 0x440) = 0;
		DbgPrint("pbw:进程隐藏！\n" );
		//监控

	

	pirp->IoStatus.Status = STATUS_SUCCESS;
	pirp->IoStatus.Information = sizeof(int);//返回给DeviceIoControl中的 倒数第二个参数lpBytesReturned
	IoCompleteRequest(pirp, IO_NO_INCREMENT);//调用方已完成所有I/O请求处理操作 并且不增加优先级 
	DbgPrint("pbw:离开派遣函数\n");

}

OB_PREOP_CALLBACK_STATUS preOperationCallBack(_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	RegistrationContext;
	PEPROCESS peprocess = (PEPROCESS)OperationInformation->Object;
	HANDLE h = PsGetProcessId(peprocess);
	if (h == realPid)
	{
		PUCHAR ImageFileName = (PUCHAR)peprocess + 0x5a8;

		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{

			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = PROCESS_ALL_ACCESS;
			OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = PROCESS_ALL_ACCESS;

			
			
		}
		return OB_PREOP_SUCCESS;
	}
	return OB_PREOP_SUCCESS;
};

void handleCallback()
{
	OB_CALLBACK_REGISTRATION callBackRegistration = { 0 };
	callBackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	callBackRegistration.OperationRegistrationCount = 1;
	UNICODE_STRING altitude;
	RtlInitUnicodeString(&altitude, L"32444");

	callBackRegistration.Altitude = altitude;
	callBackRegistration.RegistrationContext = NULL;

	OB_OPERATION_REGISTRATION operationRegistration = { 0 };
	operationRegistration.ObjectType = PsProcessType;
	operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	operationRegistration.PreOperation = (POB_PRE_OPERATION_CALLBACK)preOperationCallBack;
	operationRegistration.PostOperation = NULL;
	callBackRegistration.OperationRegistration = &operationRegistration;

	NTSTATUS status;
	status = ObRegisterCallbacks(&callBackRegistration, &regHandle);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("pbw:注册失败\n");
	}
	DbgPrint("pbw:启动进程回调监控~");

	return;
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
				ProtectProcess(pirp, device->DriverObject);
				return STATUS_SUCCESS;
			}
			if (code == REALPROCESSID)
			{	
				
					int* Buffer = (int*)pirp->AssociatedIrp.SystemBuffer;
					realPid = (HANDLE)*Buffer;
					handleCallback();
					DbgPrint("pbw: realpid: %d\n", realPid);
					return STATUS_SUCCESS;
			}

			if (code == FILETOKERNEL)
			{
				
				int* Buffer = (int*)pirp->AssociatedIrp.SystemBuffer;
				Filehandle = (HANDLE)*Buffer;
				NTSTATUS status;
				status	=	ZwClose(Filehandle);

				DbgPrint("pbw:FILE HANDLE:%d\nNTSTATUS：%d\n", Filehandle,status);
				if (!NT_SUCCESS(status))
				{
					DbgPrint("pbw:zwCloseHandle失败, 行号=%d \n", __LINE__);
				}
				return STATUS_SUCCESS;
			}
			break; 
		}
		

		case IRP_MJ_CREATE: //CreateFile
		{
			

			DbgPrint("pbw:用户层调用了 CreateFile \n" );
			
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