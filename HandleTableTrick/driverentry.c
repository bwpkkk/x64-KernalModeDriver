#include<ntifs.h> //ntddk.h
#include <ntstatus.h>
#include "IRP.h"
#define   符号链接名 L"\\??\\PBW123"
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
	
	DbgPrint("pbw:进入了 DeleteDevice例程\n");
	if (pDriver->DeviceObject) //驱动设备指针
	{

		//删除符号链接

		UNICODE_STRING uzSymbolName; 	 
		RtlInitUnicodeString(&uzSymbolName, 符号链接名);
		DbgPrint("pbw:删除符号链接=%wZ\n", &uzSymbolName);
		IoDeleteSymbolicLink(&uzSymbolName);
		//
		DbgPrint("pbw:删除驱动设备\n");
		IoDeleteDevice(pDriver->DeviceObject);

	}
	DbgPrint("pbw:退出 DeleteDevice例程\n");
}

void Driverunload(PDRIVER_OBJECT  DriverObject)
{
	
	DriverObject;
	DbgPrint("pbw:进入卸载例程DriverObject=%p 行号=%d \n", DriverObject, __LINE__);
	NTSTATUS status;
	if (Filehandle != -1 && Filehandle != 0)
	{
		status= ZwClose(Filehandle);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("pbw:ObCloseHandle失败, 行号=%d \n", __LINE__);
		}

		DbgPrint("pbw:内核层CLOSE HANDLE, 行号=%d \n", __LINE__);
		Filehandle = 0;
	}

	if (regHandle)
	{
		ObUnRegisterCallbacks(regHandle); DbgPrint("关闭回调监控~");
		regHandle = NULL;
	}
	
	DeleteDevice(DriverObject);
}


NTSTATUS CreateDevice(PDRIVER_OBJECT driver)
{
	NTSTATUS status;
	UNICODE_STRING MyDriver;     //驱动字符串
	PDEVICE_OBJECT device = NULL;//用于存放设备对象
	RtlInitUnicodeString(&MyDriver, L"\\DEVICE\\PBWDriver");   //驱动设备名字 \\DEVICE\\名字
	
	status = IoCreateDevice(driver, sizeof(driver->DriverExtension), &MyDriver, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device);
	//返回 驱动设备指针
	if (status == STATUS_SUCCESS)//STATUS_SUCCESS)
	{
		DbgPrint("pbw:驱动设备对象创建成功，OK \n");
		//创建符号链接
		UNICODE_STRING uzSymbolName; //符号链接名字		 
		//  L"\\??\\名字
		RtlInitUnicodeString(&uzSymbolName, 符号链接名); //CreateFile ReadFile WriteFile DeveicIoControl IRP_MJ_CREATE
		status = IoCreateSymbolicLink(&uzSymbolName, &MyDriver);
		if (status == STATUS_SUCCESS)
		{
			DbgPrint("pbw:创建符号链接 %wZ 成功\n ", &uzSymbolName);
		}
		else
		{
			DbgPrint("pbw:创建符号链接 %wZ 失败 status=%X\n", &uzSymbolName, status);
		}
	}
	else
	{

		DbgPrint("pbw:驱动设备对象创建失败，删除设备\n");
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
	DbgPrint("pbw: DriverEntry入口点 DriverObject=%p 行号=%d\n", DriverObject, __LINE__); //Debug


	DbgPrint("pbw: RegistryPath=%ws\n", RegistryPath->Buffer); //Unicode 宽字符
	return 0;
}