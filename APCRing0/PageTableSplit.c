#include"PageTableSplit.h"

typedef struct PTEx64 {
	ULONG64 valid : 1;  //[0]
	ULONG64 write : 1;   //[1]
    ULONG64 owner : 1;   //[2]
	ULONG64 writethrough : 1;   //[3]
	ULONG64 cachedisable : 1;   //[4
	ULONG64 accessed : 1;   //[5
	ULONG64 dirty : 1;   //[6]
	ULONG64 largepage : 1;   //[7]
	ULONG64 global : 1;   //[8]
	ULONG64 copy_on_write : 1;   //[9]
	ULONG64 prototype : 1;   //[10]
	ULONG64 reserved : 1;   //[11]
	ULONG64 page_frame_number: 36;   //[12:47]
	ULONG64 reserved1 : 4;           //[48:51]
	ULONG64 software_ws_index : 11;           //[52:62]
	ULONG64 no_execute : 1;           //63
}  PTEx64,*PPTEx64;


ULONG64 GetPTEBase()
{
	
	ULONG64 PTEBase = 0xFFFFF68000000000;
	RTL_OSVERSIONINFOW version = { 0 };
	RtlGetVersion(&version);

	if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601)
	{
		return PTEBase;
	}

	else
	{
		UNICODE_STRING str = { 0 };
		RtlInitUnicodeString(&str,L"MmGetVirtualForPhysical");
		PUCHAR funcAddr= (PUCHAR)MmGetSystemRoutineAddress(&str);
		if (funcAddr == NULL)
		{
			DbgPrint("Address is null\n");
		}
		PTEBase = *(PULONG64)(funcAddr + 0x22);
		return PTEBase;
	}


	return PTEBase;
}

ULONG64 GetPTE(ULONG64 linearAddress)
{
	
	ULONG64 pte=((linearAddress >> 9) & 0x7FFFFFFFF8) + GetPTEBase();
	return pte;
}

ULONG64 GetPDE(ULONG64 linearAddress)
{
	
	ULONG64 pde = ((GetPTE(linearAddress) >> 9) & 0x7FFFFFFFF8) + GetPTEBase();
	return pde;
}

ULONG64 GetPDPTE(ULONG64 linearAddress)
{
	ULONG64 pdpte = ((GetPDE(linearAddress) >> 9) & 0x7FFFFFFFF8) + GetPTEBase();
	return pdpte;
}

ULONG64 GetPML4(ULONG64 linearAddress)
{
	
	ULONG64 pml4 = ((GetPDPTE(linearAddress) >> 9) & 0x7FFFFFFFF8) + GetPTEBase();
	return pml4;
}



BOOLEAN SetExecutePage(ULONG64 addr, ULONG64 size)
{
	ULONG64 startaddr = addr & 0xFFFFF000;
	ULONG64 endaddr = (addr+size) & 0xFFFFF000;

	

	while (endaddr >= startaddr)
	{
		PPTEx64 pde = GetPDE(startaddr);
		
		if (MmIsAddressValid(pde) && pde->valid)//
		{

			pde->no_execute = 0;
			pde->write = 1;
		}
		else
			return FALSE;

		PPTEx64 pte = GetPTE(startaddr);
		if (MmIsAddressValid(pte) && pde->valid)//&& pte->valid
		{
			
			pte->no_execute = 0;
			pde->write = 1;
		}
		else
			return FALSE;
		startaddr += PAGE_SIZE;
	}

	return TRUE;
}


PVOID AllocateMemory(HANDLE pid, SIZE_T size)
{
	PEPROCESS peprocess = {0};
	NTSTATUS status=PsLookupProcessByProcessId(pid, &peprocess);
	
	PVOID baseaddr=0;

	if (!NT_SUCCESS(status))
	{
		DbgPrint("EPROCESS ªÒ»° ß∞‹°£\n");
		return 0;
	}

	KAPC_STATE kapc_state = { 0 };
	KeStackAttachProcess(peprocess,&kapc_state);
	
	status=ZwAllocateVirtualMemory(NtCurrentProcess(), &baseaddr,0,&size,MEM_COMMIT,PAGE_READWRITE);
	
	DbgPrint("PML4E: %p\nPDPTE: %p\nPdE: %p\nPtE: %p\n", GetPML4(baseaddr),GetPDPTE(baseaddr),GetPDE(baseaddr),GetPTE(baseaddr));
	

	if (NT_SUCCESS(status))
	{
		
		memset(baseaddr,0,size);
		BOOLEAN returnval=SetExecutePage(baseaddr,size);
		if (!returnval)
		{
			DbgPrint("SetExecutePage ß∞‹°£\n");
		}
	}
	

	KeUnstackDetachProcess(&kapc_state);
	
	
	return baseaddr;
}