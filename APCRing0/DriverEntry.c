#include<ntifs.h>
#include"InsertAPC.h"

#define   ���������� L"\\??\\BWP"

void Driverunload(PDRIVER_OBJECT  DriverObject)
{
	// ���� ɾ���������� ɾ�������豸
	DriverObject;
	DbgPrint("pbw:����ж������DriverObject=%p �к�=%d \n", DriverObject, __LINE__);

	

}







NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	
	RegistryPath;
	DriverObject->DriverUnload = Driverunload;

	insertUserApc(14368);
	
	
	DbgPrint("pbw: DriverEntry��ڵ� DriverObject=%p �к�=%d\n", DriverObject, __LINE__); //Debug

	
	

	return 0;
}