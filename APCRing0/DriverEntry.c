#include<ntifs.h>
#include"InsertAPC.h"

#define   符号链接名 L"\\??\\BWP"

void Driverunload(PDRIVER_OBJECT  DriverObject)
{
	// 并且 删除符号链接 删除驱动设备
	DriverObject;
	DbgPrint("pbw:进入卸载例程DriverObject=%p 行号=%d \n", DriverObject, __LINE__);

	

}







NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	
	RegistryPath;
	DriverObject->DriverUnload = Driverunload;

	insertUserApc(14368);
	
	
	DbgPrint("pbw: DriverEntry入口点 DriverObject=%p 行号=%d\n", DriverObject, __LINE__); //Debug

	
	

	return 0;
}