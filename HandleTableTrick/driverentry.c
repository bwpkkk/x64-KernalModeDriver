#include<ntifs.h> //ntddk.h
#include <ntstatus.h>
#include "IRP.h"
#define   ���������� L"\\??\\PBW123"
#include "myfunction.h"
#include "PageTableSplit.h"
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;

	PVOID PatchInformation;

} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;



extern HANDLE Pid,realPid,Filehandle;
extern PVOID regHandle;





void DeleteDevice(PDRIVER_OBJECT pDriver)
{	
	
	DbgPrint("pbw:������ DeleteDevice����\n");
	if (pDriver->DeviceObject) //�����豸ָ��
	{

		//ɾ����������

		UNICODE_STRING uzSymbolName; 	 
		RtlInitUnicodeString(&uzSymbolName, ����������);
		DbgPrint("pbw:ɾ����������=%wZ\n", &uzSymbolName);
		IoDeleteSymbolicLink(&uzSymbolName);
		//
		DbgPrint("pbw:ɾ�������豸\n");
		IoDeleteDevice(pDriver->DeviceObject);

	}
	DbgPrint("pbw:�˳� DeleteDevice����\n");
}

void Driverunload(PDRIVER_OBJECT  DriverObject)
{
	
	DriverObject;
	DbgPrint("pbw:����ж������DriverObject=%p �к�=%d \n", DriverObject, __LINE__);
	NTSTATUS status;
	if (Filehandle != -1 && Filehandle != 0)
	{
		status= ZwClose(Filehandle);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("pbw:ObCloseHandleʧ��, �к�=%d \n", __LINE__);
		}

		DbgPrint("pbw:�ں˲�CLOSE HANDLE, �к�=%d \n", __LINE__);
		Filehandle = 0;
	}

	if (regHandle)
	{
		ObUnRegisterCallbacks(regHandle); DbgPrint("�رջص����~");
		regHandle = NULL;
	}
	
	DeleteDevice(DriverObject);
}


NTSTATUS CreateDevice(PDRIVER_OBJECT driver)
{
	NTSTATUS status;
	UNICODE_STRING MyDriver;     //�����ַ���
	PDEVICE_OBJECT device = NULL;//���ڴ���豸����
	RtlInitUnicodeString(&MyDriver, L"\\DEVICE\\PBWDriver");   //�����豸���� \\DEVICE\\����
	
	status = IoCreateDevice(driver, sizeof(driver->DriverExtension), &MyDriver, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device);
	//���� �����豸ָ��
	if (status == STATUS_SUCCESS)//STATUS_SUCCESS)
	{
		DbgPrint("pbw:�����豸���󴴽��ɹ���OK \n");
		//������������
		UNICODE_STRING uzSymbolName; //������������		 
		//  L"\\??\\����
		RtlInitUnicodeString(&uzSymbolName, ����������); //CreateFile ReadFile WriteFile DeveicIoControl IRP_MJ_CREATE
		status = IoCreateSymbolicLink(&uzSymbolName, &MyDriver);
		if (status == STATUS_SUCCESS)
		{
			DbgPrint("pbw:������������ %wZ �ɹ�\n ", &uzSymbolName);
		}
		else
		{
			DbgPrint("pbw:������������ %wZ ʧ�� status=%X\n", &uzSymbolName, status);
		}
	}
	else
	{

		DbgPrint("pbw:�����豸���󴴽�ʧ�ܣ�ɾ���豸\n");
		IoDeleteDevice(device);
	}
	return status;
}






NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{

	RegistryPath;
	PLDR_DATA_TABLE_ENTRY ldr=(PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	ldr->Flags |= 0x20;
	DriverObject->DriverUnload = Driverunload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IRP_CALL; //IRP_CREATE_CALL
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IRP_CALL; //IRP_CLOSE_CALL
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IRP_CALL;

	CreateDevice(DriverObject);
	DbgPrint("pbw: DriverEntry��ڵ� DriverObject=%p �к�=%d\n", DriverObject, __LINE__); //Debug


	DbgPrint("pbw: RegistryPath=%ws\n", RegistryPath->Buffer); //Unicode ���ַ�
	return 0;
}