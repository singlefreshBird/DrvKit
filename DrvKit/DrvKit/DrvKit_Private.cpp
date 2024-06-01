#include "DrvKit_Private.h"
#include "DrvKit_Misc.h"
#include "DrvKit_BinaryAnalyze.h"
#include <ntimage.h>

namespace DK
{
	ZwAllocateVirtualMemory_t DrvKit_Private::m_pfnZwAllocateVirtualMemory;
	ZwWriteVirtualMemory_t DrvKit_Private::m_pfnZwWriteVirtualMemory = NULL;
	ZwReadVirtualMemory_t DrvKit_Private::m_pfnZwReadVirtualMemory = NULL;
	ZwProtectVirtualMemory_t DrvKit_Private::m_pfnZwProtectVirtualMemory = NULL;
	ZwFlushInstructionCache_t DrvKit_Private::m_pfnZwFlushInstructionCache = NULL;
	ZwFreeVirtualMemory_t DrvKit_Private::m_pfnZwFreeVirtualMemory = NULL;
	ZwCreateThreadEx_t DrvKit_Private::m_pfnZwCreateThreadEx = NULL;
	ZwTerminateThread_t DrvKit_Private::m_pfnZwTerminateThread = NULL;
	ZwQueryVirtualMemory_t DrvKit_Private::m_pfnZwQueryVirtualMemory = NULL;

#ifdef _X86_
	extern"C" PSYSTEM_SERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
#endif

	PSYSTEM_SERVICE_DESCRIPTOR_TABLE DrvKit_SSDT::m_prvSSDTEntry = NULL;

	DrvKit_SSDT::DrvKit_SSDT(){}
	DrvKit_SSDT::~DrvKit_SSDT(){}

	NTSTATUS DrvKit_SSDT::RestrieveSSDTEntry()
	{
		NTSTATUS ntStatus = STATUS_SUCCESS;

		if (m_prvSSDTEntry)
		{
			return STATUS_SUCCESS;
		}

#ifdef _X86_
		m_prvSSDTEntry = KeServiceDescriptorTable;
#else
		ULONG_PTR ulNtBase = GetNtBase();
		DrvKit_BinaryAnalyze bin(KernelMode);

		if (!bin.LoadFromMap((PUCHAR)ulNtBase))
		{
			return STATUS_UNSUCCESSFUL;
		}

		ULONG nSec;
		PIMAGE_SECTION_HEADER pSecHdr = (PIMAGE_SECTION_HEADER)bin.GetImageSectionHeader(&nSec);

		for (ULONG i = 0; i < nSec; i++)
		{
			if (FlagOn(pSecHdr[i].Characteristics, IMAGE_SCN_MEM_NOT_PAGED | IMAGE_SCN_MEM_EXECUTE) &&
				!FlagOn(pSecHdr[i].Characteristics, IMAGE_SCN_MEM_DISCARDABLE) &&
				*(PULONG)pSecHdr[i].Name == 'xet.')
			{
				PVOID pFound = NULL;
				UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";
				ntStatus = DrvKit_Misc::SearchPattern(pattern, 0xCC, sizeof(pattern) - 1, (PVOID)(ulNtBase + pSecHdr[i].VirtualAddress), pSecHdr[i].Misc.VirtualSize, &pFound);
				if (NT_SUCCESS(ntStatus))
				{
					m_prvSSDTEntry = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)pFound + *(PULONG)((PUCHAR)pFound + 3) + 7);
					break;
				}
			}
		}
#endif
		return ntStatus;
	}

	ULONG_PTR DrvKit_SSDT::GetNtBase()
	{
		NTSTATUS ntStatus;
		ULONG ulSize = 0;
		PUCHAR pBuffer = NULL;
		PRTL_SYSTEM_MODULES pModuleInfo = NULL;
		ULONG_PTR ulptrCheck = 0;
		UNICODE_STRING uszCreateFile = RTL_CONSTANT_STRING(L"NtCreateFile");
		ULONG_PTR ulPtrRet = 0;

		ulptrCheck = (ULONG_PTR)MmGetSystemRoutineAddress(&uszCreateFile);

		ntStatus = ZwQuerySystemInformation(SystemModuleInformation, 0, ulSize, &ulSize);
		if ((ntStatus != STATUS_INFO_LENGTH_MISMATCH) && (ntStatus != STATUS_BUFFER_TOO_SMALL))
		{
			DrvKit_ReportError("Failed to look up system module info.\n");
			return 0;
		}

		pBuffer = new UCHAR[ulSize];
		if (pBuffer == NULL)
		{
			DrvKit_ReportError("Failed alloc memory.\n");
			return 0;
		}

		__try
		{
			ntStatus = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, ulSize, &ulSize);
			if (!NT_SUCCESS(ntStatus))
				__leave;

			pModuleInfo = (PRTL_SYSTEM_MODULES)pBuffer;
			for (ULONG i = 0; i < pModuleInfo->NumberOfModules; i++)
			{
				if ((ULONG_PTR)pModuleInfo->Modules[i].ImageBase <= ulptrCheck &&
					(ULONG_PTR)pModuleInfo->Modules[i].ImageBase + pModuleInfo->Modules[i].ImageSize > ulptrCheck)
				{
					ulPtrRet = (ULONG_PTR)pModuleInfo->Modules[i].ImageBase;
					__leave;
				}
			}
		}
		__finally
		{
			if (pBuffer)
				delete[] pBuffer;
		}

		return ulPtrRet;
	}

	PVOID DrvKit_SSDT::GetPrivateFuntion(PCHAR FuncName)
	{
		ULONG ulId = GetFunctionIndex(FuncName);
		return GetPrivateFuntion(ulId);
	}

	ULONG DrvKit_SSDT::GetFunctionIndex(PCHAR FuncName)
	/*
	* 获取NT*函数在SSDT中的索引方法如下：
	*	1.x32位下，从ntdll中获取对应Zw*或Nt*的函数地址，+1即是索引。参考：
	*
	*  NtCreateThreadEx      B8 C1 00 00 00  mov     eax, 0C1h       ; NtCreateThreadEx
	*  NtCreateThreadEx+5    BA 40 8B 30 4B  mov     edx, offset _Wow64SystemServiceCall@0 ; Wow64SystemServiceCall()
	*  NtCreateThreadEx+A    FF D2           call    edx ; Wow64SystemServiceCall() ; Wow64SystemServiceCall()
	*  NtCreateThreadEx+C    C2 2C 00
	*
	*  2.x64位下，从ntdll中获取对应Zw*或Nt*的函数地址，特征码匹配0xB8 0xCC 0xCC 0xCC 0xCC，0xCC部分是模糊匹配的意思。
	*	当然也可以直接加偏移0x4，此偏移目前在Win2k3~Win11 x64上都不变。
	*	匹配到的地址+1就是索引。参考：
	*
	*  NtCreateThreadEx      4C 8B D1                 mov     r10, rcx        ; NtCreateThreadEx
	*  NtCreateThreadEx+3    B8 BD 00 00 00           mov     eax, 0BDh
	*  NtCreateThreadEx+8    F6 04 25 08 03 FE 7F 01  test    byte ptr ds:7FFE0308h, 1
	*  NtCreateThreadEx+10   75 03                    jnz     short loc_18009D805
	*  NtCreateThreadEx+12   0F 05                    syscall                 ; Low latency system call
	*  NtCreateThreadEx+14   C3                       retn
	*/
	{
		ULONG_PTR ulptrFunc = 0;
		NTSTATUS ntStatus;
		PFILE_OBJECT pFileObj = NULL;
		ULONG ulIndex = -1;
		KAPC_STATE kApcState;
		PCONTROL_AREA pCtlArea = NULL;
		PSEGMENT pSegMent = NULL;
		UNICODE_STRING uzPath = RTL_CONSTANT_STRING(L"c:\\windows\\system32\\ntdll.dll");
		DrvKit_BinaryAnalyze bin(KernelMode);

		if (!bin.LoadFromFile(uzPath))
		{
			goto end;
		}

		ulptrFunc = (ULONG_PTR)bin.GetFunAddressFromEAT(FuncName);
		if (ulptrFunc == NULL)
		{
			goto end;
		}

		__try
		{
			if (MmIsAddressValid((PVOID)ulptrFunc))
			{
#ifdef _X86_

				ulIndex = *(PULONG)(ulptrFunc + 1);
#else
				ulIndex = *(PULONG)(ulptrFunc + 0x4);
#endif
			}

		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DrvKit_ReportException("An exception occurred during getting function.\n");
		}

	end:
		
		return ulIndex < 0xFFFF ? ulIndex : -1;
	}

	PVOID DrvKit_SSDT::GetPrivateFuntion(ULONG Index)
	{
		if (!NT_SUCCESS(RestrieveSSDTEntry()))
			return NULL;

		if (m_prvSSDTEntry == NULL)
			return NULL;

		if (Index > m_prvSSDTEntry->NumberOfServices)
			return NULL;

#ifdef _X86_
		return (PVOID)((PULONG_PTR)m_prvSSDTEntry->ServiceTableBase)[Index];
#else
		return (PUCHAR)m_prvSSDTEntry->ServiceTableBase + (((PLONG)m_prvSSDTEntry->ServiceTableBase)[Index] >> 4);
#endif
	}

	DrvKit_Private::DrvKit_Private() {}
	DrvKit_Private::~DrvKit_Private() {}

	NTSTATUS DrvKit_Private::Init()
	{
		UNICODE_STRING uszFuncName;
		NTSTATUS ntStatus = STATUS_SUCCESS;

		m_pfnZwWriteVirtualMemory = (ZwWriteVirtualMemory_t)
			DrvKit_SSDT::GetPrivateFuntion("ZwWriteVirtualMemory");

		m_pfnZwReadVirtualMemory = (ZwReadVirtualMemory_t)
			DrvKit_SSDT::GetPrivateFuntion("ZwReadVirtualMemory");

		m_pfnZwCreateThreadEx = (ZwCreateThreadEx_t)
			DrvKit_SSDT::GetPrivateFuntion("NtCreateThreadEx");

		RtlInitUnicodeString(&uszFuncName, L"ZwFreeVirtualMemory");
		m_pfnZwFreeVirtualMemory = (ZwFreeVirtualMemory_t)
			MmGetSystemRoutineAddress(&uszFuncName);

		RtlInitUnicodeString(&uszFuncName, L"ZwAllocateVirtualMemory");
		m_pfnZwAllocateVirtualMemory = (ZwAllocateVirtualMemory_t)
			MmGetSystemRoutineAddress(&uszFuncName);

		RtlInitUnicodeString(&uszFuncName, L"ZwFlushInstructionCache");
		m_pfnZwFlushInstructionCache = (ZwFlushInstructionCache_t)
			MmGetSystemRoutineAddress(&uszFuncName);

		m_pfnZwProtectVirtualMemory = (ZwProtectVirtualMemory_t)
			DrvKit_SSDT::GetPrivateFuntion("ZwProtectVirtualMemory");

		m_pfnZwTerminateThread = (ZwTerminateThread_t)
			DrvKit_SSDT::GetPrivateFuntion("ZwTerminateThread");

		RtlInitUnicodeString(&uszFuncName, L"ZwQueryVirtualMemory");
		m_pfnZwQueryVirtualMemory = (ZwQueryVirtualMemory_t)
			MmGetSystemRoutineAddress(&uszFuncName);

		if (
			m_pfnZwAllocateVirtualMemory == NULL ||
			m_pfnZwWriteVirtualMemory == NULL ||
			m_pfnZwCreateThreadEx == NULL ||
			m_pfnZwReadVirtualMemory == NULL ||
			m_pfnZwProtectVirtualMemory == NULL ||
			m_pfnZwFlushInstructionCache == NULL ||
			m_pfnZwFreeVirtualMemory == NULL ||
			m_pfnZwTerminateThread == NULL ||
			m_pfnZwQueryVirtualMemory == NULL
			)
		{
			ntStatus = STATUS_NOT_FOUND;
		}

		return ntStatus;
	}

	
};