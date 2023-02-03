#include "myfunction.h"
#include <ntifs.h>
#include "IRP.h"
#include <wdm.h>

extern HANDLE Pid;

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
   
        // 从PDRIVER_OBJECT获取DriverSection，便可获得驱动模块链表
            PLDR_DATA_TABLE_ENTRY  pDriverData = (PLDR_DATA_TABLE_ENTRY )pDriverObject->DriverSection;
       // 开始遍历双向链表
            PLDR_DATA_TABLE_ENTRY  pFirstDriverData = pDriverData;
        
         do
            {
              if ((0 < pDriverData->BaseDllName.Length) ||
                      (0 < pDriverData->FullDllName.Length))
                   {
                        // 显示
                         DbgPrint("BaseDllName=%ws,\tDllBase=0x%p,\tSizeOfImage=0x%X,\tFullDllName=%ws\n",
                                   pDriverData->BaseDllName.Buffer, pDriverData->DllBase,
                                   pDriverData->SizeOfImage, pDriverData->FullDllName.Buffer);
                         //BaseDllName.Buffer是PWCH，也就是宽字符串，所以自己定义的moudName也要是PWCHAR类型
                           if (!_stricmp(moudName, (PCHAR)pDriverData->BaseDllName.Buffer))
                         {
                            DbgPrint("find target : BaseDllName=%ws,\tDllBase=0x%p,\tSizeOfImage=0x%X,\tFullDllName=%ws\n",
                                        pDriverData->BaseDllName.Buffer, pDriverData->DllBase,
                                       pDriverData->SizeOfImage, pDriverData->FullDllName.Buffer);
                                        *pSize = pDriverData->SizeOfImage;
                                         return pDriverData->DllBase;
                             }
            
                        }
                // 下一个
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
                 // 遍历特征码
                     for (j = 0; j < ulSpecialCodeLength; j++)
                    {
                         // 判断地址是否有效  ntoskrnl.exe有时地址无效，蓝屏报错：PAGE FAULED IN NONPAGED AREA
                            if (FALSE == MmIsAddressValid((PVOID)(i + j)))
                            {
                                break;
                            }
                        // 匹配特征码
                            if (*(PUCHAR)(i + j) != pSpecialCode[j])
                            {
                                break;
                             }
                     }
                // 匹配成功
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
    DbgPrint("pbw: threadHandle: %p\n", threadHandle);
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
        DbgPrint(" pbw:KeSuspendThreadaddr 未获取成功 \n");
        return status;
    }

    KeSuspendThreadProc KeSuspendThreadaddr2 = (KeSuspendThreadProc)KeSuspendThreadaddr;

   
    PKTHREAD kthread = (PKTHREAD)(Thread);
    status = KeSuspendThreadaddr2(kthread);
    if (!NT_SUCCESS(status))
    {
        DbgPrint(" pbw:线程挂起失败 \n");
    }
    DbgPrint("pbw:KeSuspendThreadaddr: %p, 线程挂起 \n", KeSuspendThreadaddr2);


    return 0;
}

NTSTATUS KeResumeThread(PETHREAD Thread, PVOID addr)
{
    typedef NTSTATUS(*KeResumeThreadProc) (
        IN PKTHREAD Thread

        );

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR KeResumeThreadaddr = addr;


    if (!KeResumeThreadaddr)
    {
        DbgPrint(" pbw:KeResumeThreadaddr 未获取成功 \n");
        return status;
    }

    KeResumeThreadProc KeResumeThreadaddr2 = (KeResumeThreadProc)KeResumeThreadaddr;


    PKTHREAD kthread = (PKTHREAD)(Thread);
    status = KeResumeThreadaddr2(kthread);
    if (!NT_SUCCESS(status))
    {
        DbgPrint(" 线程恢复失败 \n");
    }
    DbgPrint("pbw:KeResumeThreadaddr: %p, 线程恢复 \n", KeResumeThreadaddr2);


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
        DbgPrint("pbw: KeResumeThreadaddr 未获取成功 \n");
        return status;
    }

    KeResumeThreadProc KeResumeThreadaddr2 = (KeResumeThreadProc)KeResumeThreadaddr;


    PKTHREAD kthread = (PKTHREAD)(Thread);
    status = KeResumeThreadaddr2(kthread);
    if (!NT_SUCCESS(status))
    {
        DbgPrint(" pbw:线程恢复失败 \n");
    }
    DbgPrint("pbw:KeResumeThreadaddr: %p, 线程恢复 \n", KeResumeThreadaddr2);


    return 0;
}


NTSTATUS PsSuspendThread(PETHREAD Thread,  PULONG PreviousSuspendCount)
{
    //4883EC304C8BF2488BF9836424200065488B3425880100004889742470
    //4883EC* 4C8BF2488BF983****    65488B3425****    4889742470

   /* typedef NTSTATUS(*PsSuspendThreadProc) (
        IN PETHREAD Thread,
        OUT PULONG PreviousSuspendCount OPTIONAL
        );

    NTSTATUS status=STATUS_UNSUCCESSFUL;
    ULONG_PTR PsSuspendThreadaddr= GetAddressByCode("ntoskrnl.exe","PAGE","4883EC*4C8BF2488BF983****65488B3425****4889742470",-0x11);
  
    if (!PsSuspendThreadaddr)
    {
        DbgPrint(" PsSuspendThreadaddr 未获取成功 %p\n");
        return status;
    }

    PsSuspendThreadProc PsSuspendThreadaddr2 = (PsSuspendThreadProc)PsSuspendThreadaddr;

    DbgBreakPoint();
    
    status = PsSuspendThreadaddr2(Thread, PreviousSuspendCount);
    if (!NT_SUCCESS(status))
    {
        DbgPrint(" 线程挂起失败 \n");
    }
    DbgPrint("PsSuspendThreadaddr: %p, 线程挂起 \n",PsSuspendThreadaddr2);
    */

    //57415641574883EC30488BF9440F20C3B902000000440F22C1
    //57415641574883EC*488BF9440F20C3B9****440F22C1

    
}




PVOID SuspendA11Thread(PVOID Kefunc)
{    
    PEPROCESS peprocess  = 0;
    NTSTATUS status;
    status = PsLookupProcessByProcessId(Pid,&peprocess);
    if(!NT_SUCCESS(status))
    {   
        DbgPrint("pbw:没找到peprocess,行号：%d",__LINE__);
        return 0;
    }
  

    PUCHAR pkprocess = (PUCHAR)((PUCHAR)peprocess + 0x30);
 

    PLIST_ENTRY pkthread = (PLIST_ENTRY)*(ULONG64*)pkprocess;
    
    PLIST_ENTRY Firstpkthread = pkthread->Flink;
    PUCHAR tempThread;
    while (Firstpkthread->Flink != pkthread)
    {   
        tempThread = (PUCHAR)Firstpkthread-0x2f8;
        
       
        KeSuspendThread((PETHREAD)tempThread,Kefunc);
        DbgPrint("pbw:PKTHREAD:%p已挂起,行号：%d\n", tempThread, __LINE__);
        Firstpkthread = Firstpkthread->Flink;
    } 
  
    return 0;
}

PVOID ResumeAllThread(PVOID Keresumefunc)
{   
    PEPROCESS peprocess = 0;
    NTSTATUS status;
    status = PsLookupProcessByProcessId(Pid, &peprocess);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("pbw:没找到peprocess,行号：%d", __LINE__);
        return 0;
    }
  

    PUCHAR pkprocess = (PUCHAR)((PUCHAR)peprocess + 0x30);
    

    PLIST_ENTRY pkthread = (PLIST_ENTRY) * (ULONG64*)pkprocess;

    PLIST_ENTRY Firstpkthread = pkthread->Flink;
    PUCHAR tempThread;
    while (Firstpkthread->Flink != pkthread)
    {
        tempThread = (PUCHAR)Firstpkthread - 0x2f8;

        KeResumeThreadWin11((PETHREAD)tempThread, Keresumefunc);
        
        DbgPrint("pbw:PKTHREAD:%p已恢复,行号：%d\n", tempThread, __LINE__);
        Firstpkthread = Firstpkthread->Flink;
    }

   
    return 0;
}







