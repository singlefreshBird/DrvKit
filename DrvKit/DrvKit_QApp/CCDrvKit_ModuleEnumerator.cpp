#include "CCDrvKit_ModuleEnumerator.h"
#include <TlHelp32.h>
#include <psapi.h>
#include <global.h>


CCDrvKit_ModuleEnumerator::CCDrvKit_ModuleEnumerator()
{
	HMODULE hNtdll = GetModuleHandleW(L"ntdll");

	assert(hNtdll != nullptr);

	_pfnNtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(hNtdll, "NtReadVirtualMemory");
	_pfnNtWow64ReadVirtualMemory64 = (NtWow64ReadVirtualMemory64_t)GetProcAddress(hNtdll, "NtWow64ReadVirtualMemory64");
	_pfnNtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	_pfnNtWow64QueryInformationProcess64 = (NtWow64QueryInformationProcess64_t)GetProcAddress(hNtdll, "NtWow64QueryInformationProcess64");
	if (_pfnNtReadVirtualMemory == nullptr) DebugPrintW(L"Can't find NtReadVirtualMemory.\n");
	if (_pfnNtWow64ReadVirtualMemory64 == nullptr) DebugPrintW(L"Can't find NtWow64ReadVirtualMemory64.\n");
	if (_pfnNtQueryInformationProcess == nullptr) DebugPrintW(L"Can't find NtQueryInformationProcess.\n");
	if (_pfnNtWow64QueryInformationProcess64 == nullptr) DebugPrintW(L"Can't find NtWow64QueryInformationProcess64.\n");
}

bool CCDrvKit_ModuleEnumerator::Enumerate(void* Param, uint32_t ProcessId)
{
	bool bRet = false;
	MODULEENTRY32W modEnt;
	modEnt.dwSize = sizeof(modEnt);

	if (Param == nullptr) return false;

	module_collection_ptr pMod_cell = (module_collection_ptr)Param;

	do 
	{
		unique_handle hProc(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId));

		if (hProc.get() == nullptr) break;

		
		SYSTEM_INFO sysInfo;
		GetNativeSystemInfo(&sysInfo);

		if (sysInfo.dwProcessorType == PROCESSOR_INTEL_IA64 || sysInfo.dwProcessorType == PROCESSOR_AMD_X8664)
		{
			BOOL bWow64;
			if (!IsWow64Process(hProc.get(), &bWow64)) break;

			if (bWow64)
			{
				bRet = EnumModuleInfoByPeb<ULONG>(hProc.get(), pMod_cell);
			}
			else
			{
				bRet = EnumModuleInfoByPeb<ULONG64>(hProc.get(), pMod_cell);
			}
		}
		else
		{
			bRet = EnumModuleInfoByPeb<ULONG>(hProc.get(), pMod_cell);
		}
		

	} while (false);
	
	return bRet;
}

CCModule::CCModule(ULONG64 BaseAddress, size_t ModuleSize, QString ModuleName, QString ModulePath):
	m_BaseAddr(BaseAddress),
	m_ModuleSize(ModuleSize),
	m_ModuleName(ModuleName),
	m_ModulePath(ModulePath)
{}

CCModule::~CCModule(){}

const QString& CCModule::GetName()const
{
	return m_ModuleName;
}

const QString& CCModule::GetFullPath()const
{
	return m_ModulePath;
}

const size_t CCModule::GetSize()const
{
	return m_ModuleSize;
}

const ULONG64 CCModule::GetBaseAddress()const
{
	return m_BaseAddr;
}

bool CCDrvKit_ModuleEnumerator::ReadRemoteMemory(HANDLE Prochandle, PVOID Dest, SIZE_T ReadBytes, ULONG Src)
{
	if (Dest == nullptr || Src == 0) return false;

	if (_pfnNtReadVirtualMemory)
	{
		return NT_SUCCESS(_pfnNtReadVirtualMemory(Prochandle, (PVOID)Src, Dest, ReadBytes, NULL));
	}

	return false;
	
}

bool CCDrvKit_ModuleEnumerator::ReadRemoteMemory(HANDLE Prochandle, PVOID Dest, SIZE_T ReadBytes, ULONG64 Src)
{
	if (Dest == nullptr || Src == 0) return false;

	if (_pfnNtWow64ReadVirtualMemory64)
	{
		return NT_SUCCESS(_pfnNtWow64ReadVirtualMemory64(Prochandle, Src, Dest, ReadBytes, NULL));
	}

	return false;
}

template<typename _Ty>
ULONG64 CCDrvKit_ModuleEnumerator::GetPeb(HANDLE Prochandle, typename _PEB_T<_Ty>::type* Peb)
{
	if (std::is_same<_Ty, ULONG>::value)
	{
		PROCESS_BASIC_INFORMATION ProcessBasicInfo = { 0 };
		ULONG ReturnLength = 0;

		if (NT_SUCCESS(_pfnNtQueryInformationProcess(Prochandle, ProcessBasicInformation, &ProcessBasicInfo,
			(ULONG)sizeof(ProcessBasicInfo), &ReturnLength)) && Peb)
		{
			ReadRemoteMemory(Prochandle, Peb, sizeof(_PEB_T<_Ty>::type), (ULONG)ProcessBasicInfo.PebBaseAddress);
		}

		return (ULONG64)ProcessBasicInfo.PebBaseAddress;
	}
	else
	{
		_PROCESS_BASIC_INFORMATION_<_Ty> ProcessBasicInfo = { 0 };
		ULONG ReturnLength = 0;
		if (NT_SUCCESS(_pfnNtWow64QueryInformationProcess64(Prochandle, ProcessBasicInformation, &ProcessBasicInfo,
			(ULONG)sizeof(ProcessBasicInfo), &ReturnLength)) && Peb)
		{
			_pfnNtWow64ReadVirtualMemory64(Prochandle, ProcessBasicInfo.PebBaseAddress, Peb, sizeof(_PEB_T<_Ty>::type), NULL);
		}
		return (ULONG64)ProcessBasicInfo.PebBaseAddress;
	}
}

template<typename _Ty>
bool CCDrvKit_ModuleEnumerator::EnumModuleInfoByPeb(HANDLE ProcessHandle, module_collection_ptr ModInfoSet)
{
	typename _PEB_T<_Ty>::type peb = { { { 0 } } };
	_PEB_LDR_DATA_<_Ty> PebLdrData = { 0 };

	if (GetPeb<_Ty>(ProcessHandle, &peb) != 0 && 
		ReadRemoteMemory(ProcessHandle, &PebLdrData, sizeof(PebLdrData),peb.Ldr) == true)
	{
		for (_Ty CheckPtr = PebLdrData.InLoadOrderModuleList.Flink;
			CheckPtr != (peb.Ldr + FIELD_OFFSET(_PEB_LDR_DATA_<_Ty>, InLoadOrderModuleList));
			)
		{
			wchar_t wzModuleFullPathData[MAX_PATH] = { 0 };
			wchar_t wzModuleName[0x40] = { 0 };
			_LDR_DATA_TABLE_ENTRY_<_Ty> LdrDataTableEntry = { { 0 } };

			if (!ReadRemoteMemory(
				ProcessHandle,
				&LdrDataTableEntry,
				sizeof(LdrDataTableEntry),
				CheckPtr))
			{
				continue;
			}

			// 取DLL路径
			if (!ReadRemoteMemory(
				ProcessHandle,
				wzModuleFullPathData,
				LdrDataTableEntry.FullDllName.BufferLength,
				LdrDataTableEntry.FullDllName.BufferData))
			{
				continue;
			}

			// 取DLL名字
			if (!ReadRemoteMemory(
				ProcessHandle,
				wzModuleName,
				sizeof(wzModuleName),
				LdrDataTableEntry.BaseDllName.BufferData))
			{
				continue;
			}

			CCModule mod(
				LdrDataTableEntry.DllBase,
				(size_t)LdrDataTableEntry.SizeOfImage,
				QString::fromStdWString(wzModuleName),
				QString::fromStdWString(wzModuleFullPathData));

			ModInfoSet->emplace(ModInfoSet->end(), mod);
			
			if (!ReadRemoteMemory(ProcessHandle, &CheckPtr, sizeof(CheckPtr), CheckPtr)) break;

		}
		return true;
	}
	return false;
}