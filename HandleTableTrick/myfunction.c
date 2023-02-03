#include "myfunction.h"
#include <ntifs.h>

#include <wdm.h>

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



PVOID FindModule(PDRIVER_OBJECT pDriverObject, PWCHAR moudName, PULONG pSize)
 {
   
        // ��PDRIVER_OBJECT��ȡDriverSection����ɻ������ģ������
            PLDR_DATA_TABLE_ENTRY  pDriverData = (PLDR_DATA_TABLE_ENTRY )pDriverObject->DriverSection;
       // ��ʼ����˫������w
            PLDR_DATA_TABLE_ENTRY  pFirstDriverData = pDriverData;
        
         do
            {
              if ((0 < pDriverData->BaseDllName.Length) ||
                      (0 < pDriverData->FullDllName.Length))
                   {
                        // ��ʾ
                         DbgPrint("BaseDllName=%ws,\tDllBase=0x%p,\tSizeOfImage=0x%X,\tFullDllName=%ws\n",
                                   pDriverData->BaseDllName.Buffer, pDriverData->DllBase,
                                   pDriverData->SizeOfImage, pDriverData->FullDllName.Buffer);
                         //BaseDllName.Buffer��PWCH��Ҳ���ǿ��ַ����������Լ������moudNameҲҪ��PWCHAR����
                           if (!_stricmp(moudName, (PCHAR)pDriverData->BaseDllName.Buffer))
                         {
                            DbgPrint("find target : BaseDllName=%ws,\tDllBase=0x%p,\tSizeOfImage=0x%X,\tFullDllName=%ws\n",
                                        pDriverData->BaseDllName.Buffer, pDriverData->DllBase,
                                       pDriverData->SizeOfImage, pDriverData->FullDllName.Buffer);
                                        *pSize = pDriverData->SizeOfImage;
                                         return pDriverData->DllBase;
                             }
            
                        }
                // ��һ��
                    pDriverData = (PLDR_DATA_TABLE_ENTRY )pDriverData->InLoadOrderLinks.Flink;
        
                } while (pFirstDriverData != pDriverData);
        
                 return NULL;
         }



PVOID FindFun(PVOID pSearchBeginAddr, ULONG ulSearchLength, PUCHAR pSpecialCode, ULONG ulSpecialCodeLength)
 {
         PVOID pDestAddr = NULL;
         PUCHAR pBeginAddr = (PUCHAR)pSearchBeginAddr;
         PUCHAR pEndAddr = pBeginAddr + ulSearchLength;
         PUCHAR i = NULL;
         ULONG j = 0;
    
             for (i = pBeginAddr; i <= pEndAddr; i++)
             {
                 // ����������
                     for (j = 0; j < ulSpecialCodeLength; j++)
                    {
                         // �жϵ�ַ�Ƿ���Ч  ntoskrnl.exe��ʱ��ַ��Ч����������PAGE FAULED IN NONPAGED AREA
                            if (FALSE == MmIsAddressValid((PVOID)(i + j)))
                            {
                                break;
                            }
                        // ƥ��������
                            if (*(PUCHAR)(i + j) != pSpecialCode[j])
                            {
                                break;
                             }
                     }
                // ƥ��ɹ�
                     if (j >= ulSpecialCodeLength)
                     {
                        pDestAddr = (PVOID)i;
                        break;
                     }
                     
             }
             
             return pDestAddr;
     }



NTSTATUS NTAPI ZwGetNextThread(
    __in HANDLE ProcessHandle,
    __in HANDLE ThreadHandle,
    __in ACCESS_MASK DesiredAccess,
    __in ULONG HandleAttributes,
    __in ULONG Flags,
    __out PHANDLE NewThreadHandle)
{

    typedef NTSTATUS (NTAPI *ZwGetNextThreadProc)(
        __in HANDLE ProcessHandle,
        __in HANDLE ThreadHandle,
        __in ACCESS_MASK DesiredAccess,
        __in ULONG HandleAttributes,
        __in ULONG Flags,
        __out PHANDLE NewThreadHandle
        );

   
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING funcname = {0};
    RtlInitUnicodeString(&funcname,L"ZwGetNextThread");
    ZwGetNextThreadProc funcAddr = NULL;
    funcAddr =(ZwGetNextThreadProc)MmGetSystemRoutineAddress(&funcname);
    if (funcAddr)
    {
        status = (*funcAddr)(ProcessHandle,ThreadHandle,DesiredAccess,HandleAttributes,Flags, NewThreadHandle);
    } 

    return status;

}




PETHREAD GetMainThread(PEPROCESS ptrProcess)
{

    PETHREAD pethread = { 0 };
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    KAPC_STATE kapc_state = { 0 };
    KeStackAttachProcess(ptrProcess,&kapc_state);
    
    HANDLE threadHandle = 0;
    status= ZwGetNextThread(NtCurrentProcess(),0,THREAD_ALL_ACCESS,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,0,&threadHandle);
    
    if (NT_SUCCESS(status))
    {
        status = ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, *PsThreadType,KernelMode, (PVOID)&pethread,0);
    }
    
    KeUnstackDetachProcess(&kapc_state);

    return pethread;
    
}





NTSTATUS KeSuspendThread(PETHREAD Thread, PVOID addr)
{
    typedef NTSTATUS(*KeSuspendThreadProc) (
        IN PKTHREAD Thread

        );

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR KeSuspendThreadaddr = addr;
    

    if (!KeSuspendThreadaddr)
    {
        DbgPrint(" KeSuspendThreadaddr δ��ȡ�ɹ� \n");
        return status;
    }

    KeSuspendThreadProc KeSuspendThreadaddr2 = (KeSuspendThreadProc)KeSuspendThreadaddr;

   
    PKTHREAD kthread = (PKTHREAD)(Thread);
    status = KeSuspendThreadaddr2(kthread);
    if (!NT_SUCCESS(status))
    {
        DbgPrint(" �̹߳���ʧ�� \n");
    }
    DbgPrint("KeSuspendThreadaddr: %p, �̹߳��� \n", KeSuspendThreadaddr2);


    return 0;
}

NTSTATUS KeResumeThread(PETHREAD Thread, PVOID addr)
{
    typedef NTSTATUS(*KeResumeThreadProc) (
        IN PKTHREAD Thread

        );

    //UCHAR shellcode2[] = { 0x48,0x8b,0xc4,0x48,0x89,0x58,0x08,0x48,0x89,0x68,0x10,0x48,0x89,0x70,
    //	0x18,0x48,0x89,0x78,0x20,0x41,0x56,0x48,0x83,0xec,0x30,0x48,0x8b,0xd9 };   //WIN10X64
    //dwreturn2 = FindFun(baseAddr, size, shellcode2, 28);
    //status = KeResumeThread(temp, dwreturn2);
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR KeResumeThreadaddr = addr;


    if (!KeResumeThreadaddr)
    {
        DbgPrint(" KeResumeThreadaddr δ��ȡ�ɹ� \n");
        return status;
    }

    KeResumeThreadProc KeResumeThreadaddr2 = (KeResumeThreadProc)KeResumeThreadaddr;


    PKTHREAD kthread = (PKTHREAD)(Thread);
    status = KeResumeThreadaddr2(kthread);
    if (!NT_SUCCESS(status))
    {
        DbgPrint(" �ָ̻߳�ʧ�� \n");
    }
    DbgPrint("KeResumeThreadaddr: %p, �ָ̻߳� \n", KeResumeThreadaddr2);


    return 0;
}

NTSTATUS KeResumeThreadWin11(PETHREAD Thread, PVOID addr)
{
    typedef NTSTATUS(*KeResumeThreadProc) (
        IN PKTHREAD Thread

        );

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR KeResumeThreadaddr = addr;


    if (!KeResumeThreadaddr)
    {
        DbgPrint(" KeResumeThreadaddr δ��ȡ�ɹ� \n");
        return status;
    }

    KeResumeThreadProc KeResumeThreadaddr2 = (KeResumeThreadProc)KeResumeThreadaddr;


    PKTHREAD kthread = (PKTHREAD)(Thread);
    status = KeResumeThreadaddr2(kthread);
    if (!NT_SUCCESS(status))
    {
        DbgPrint(" �ָ̻߳�ʧ�� \n");
    }
    DbgPrint("KeResumeThreadaddr: %p, �ָ̻߳� \n", KeResumeThreadaddr2);


    return 0;
}


