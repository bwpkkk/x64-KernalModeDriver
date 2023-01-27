#include<ntifs.h> //ntddk.h
#include <ntstatus.h>

#define   符号链接名 L"\\??\\PBW123"

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

PVOID regHandle = NULL;

HANDLE realPid;


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
			//DbgPrint("%s权限已被修改\n",ImageFileName);


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


void Driverunload(PDRIVER_OBJECT  DriverObject)
{

	DriverObject;
	DbgPrint("pbw:进入卸载例程DriverObject=%p 行号=%d \n", DriverObject, __LINE__);
	if (regHandle)
	{
		ObUnRegisterCallbacks(regHandle);
		regHandle = NULL;
	}
	DbgPrint("关闭回调监控~");
	
}


NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{

	RegistryPath;
	PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	ldr->Flags |= 0x20;
	DriverObject->DriverUnload = Driverunload;
	


	DbgPrint("pbw: DriverEntry入口点 DriverObject=%p 行号=%d\n", DriverObject, __LINE__); //Debug
	realPid =	27264;
	handleCallback();


	DbgPrint("pbw: RegistryPath=%ws\n", RegistryPath->Buffer); //Unicode 宽字符
	return 0;
}