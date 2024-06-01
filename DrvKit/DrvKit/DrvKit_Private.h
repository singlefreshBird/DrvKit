#pragma once
#include "prefix.h"

namespace DK
{
	typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
	{
		PULONG_PTR ServiceTableBase;
		PULONG ServiceCounterTableBase;
		ULONG_PTR NumberOfServices;
		PUCHAR ParamTableBase;
	} SYSTEM_SERVICE_DESCRIPTOR_TABLE, * PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

	class DrvKit_SSDT
	{
	private:
		static PSYSTEM_SERVICE_DESCRIPTOR_TABLE m_prvSSDTEntry;

	private:
		DrvKit_SSDT();
		~DrvKit_SSDT();

		static NTSTATUS RestrieveSSDTEntry();
		static ULONG_PTR GetNtBase();

	public:
		static PVOID GetPrivateFuntion(PCHAR FuncName);
		static ULONG GetFunctionIndex(PCHAR FuncName);
		static PVOID GetPrivateFuntion(ULONG Index);
	};

	class DrvKit_Private
	{
	private:
		DrvKit_Private();
		~DrvKit_Private();

	public:
		static ZwAllocateVirtualMemory_t m_pfnZwAllocateVirtualMemory;
		static ZwProtectVirtualMemory_t m_pfnZwProtectVirtualMemory;
		static ZwFlushInstructionCache_t m_pfnZwFlushInstructionCache;
		static ZwWriteVirtualMemory_t m_pfnZwWriteVirtualMemory;
		static ZwReadVirtualMemory_t m_pfnZwReadVirtualMemory;
		static ZwFreeVirtualMemory_t m_pfnZwFreeVirtualMemory;
		static ZwCreateThreadEx_t m_pfnZwCreateThreadEx;
		static ZwTerminateThread_t m_pfnZwTerminateThread;
		static ZwQueryVirtualMemory_t m_pfnZwQueryVirtualMemory;

	public:
		static NTSTATUS Init();
	};
};