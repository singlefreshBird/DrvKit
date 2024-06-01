#pragma once
#include "IDrvKit_Enumerator.h"
#include <QString>
#include <vector>
#include <winternl.h>

template <typename _Ty>
struct _LIST_ENTRY_
{
	_Ty Flink;
	_Ty Blink;
};

template <typename _Ty>
struct _UNICODE_STRING_
{
	WORD BufferLength;
	WORD MaximumLength;
	_Ty BufferData;
};



template <typename _Ty, typename NGF, int A>
struct _PEB_
{
	typedef _Ty type;

	union
	{
		struct
		{
			BYTE InheritedAddressSpace;
			BYTE ReadImageFileExecOptions;
			BYTE BeingDebugged;
			BYTE BitField;
		};
		_Ty dummy01;
	};
	_Ty Mutant;
	_Ty ImageBaseAddress;
	_Ty Ldr;
	_Ty ProcessParameters;
	_Ty SubSystemData;
	_Ty ProcessHeap;
	_Ty FastPebLock;
	_Ty AtlThunkSListPtr;
	_Ty IFEOKey;
	_Ty CrossProcessFlags;
	_Ty UserSharedInfoPtr;
	DWORD SystemReserved;
	DWORD AtlThunkSListPtr32;
	_Ty ApiSetMap;
	_Ty TlsExpansionCounter;
	_Ty TlsBitmap;
	DWORD TlsBitmapBits[2];
	_Ty ReadOnlySharedMemoryBase;
	_Ty HotpatchInformation;
	_Ty ReadOnlyStaticServerData;
	_Ty AnsiCodePageData;
	_Ty OemCodePageData;
	_Ty UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	union
	{
		DWORD NtGlobalFlag;
		NGF dummy02;
	};
	LARGE_INTEGER CriticalSectionTimeout;
	_Ty HeapSegmentReserve;
	_Ty HeapSegmentCommit;
	_Ty HeapDeCommitTotalFreeThreshold;
	_Ty HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	_Ty ProcessHeaps;
	_Ty GdiSharedHandleTable;
	_Ty ProcessStarterHelper;
	_Ty GdiDCAttributeList;
	_Ty LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	_Ty ImageSubsystemMinorVersion;
	_Ty ActiveProcessAffinityMask;
	_Ty GdiHandleBuffer[A];
	_Ty PostProcessInitRoutine;
	_Ty TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	_Ty SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	_Ty pShimData;
	_Ty AppCompatInfo;
	_UNICODE_STRING_<_Ty> CSDVersion;
	_Ty ActivationContextData;
	_Ty ProcessAssemblyStorageMap;
	_Ty SystemDefaultActivationContextData;
	_Ty SystemAssemblyStorageMap;
	_Ty MinimumStackCommit;
	_Ty FlsCallback;
	_LIST_ENTRY_<_Ty> FlsListHead;
	_Ty FlsBitmap;
	DWORD FlsBitmapBits[4];
	_Ty FlsHighIndex;
	_Ty WerRegistrationData;
	_Ty WerShipAssertPtr;
	_Ty pContextData;
	_Ty pImageHeaderHash;
	_Ty TracingFlags;
	_Ty CsrServerReadOnlySharedMemoryBase;
};
typedef _PEB_<DWORD, DWORD64, 34> _PEB32_;
typedef _PEB_<DWORD64, DWORD, 30> _PEB64_;
template<typename _Ty>
struct _PEB_T
{
	typedef typename std::conditional<std::is_same<_Ty, ULONG>::value, _PEB32_, _PEB64_>::type type;
};

template<typename _Ty>
struct _PEB_LDR_DATA_
{
	unsigned long Length;
	unsigned char Initialized;
	_Ty SsHandle;
	_LIST_ENTRY_<_Ty> InLoadOrderModuleList;
	_LIST_ENTRY_<_Ty> InMemoryOrderModuleList;
	_LIST_ENTRY_<_Ty> InInitializationOrderModuleList;
	_Ty EntryInProgress;
	unsigned char ShutdownInProgress;
	_Ty ShutdownThreadId;
};


template<typename _Ty>
struct _LDR_DATA_TABLE_ENTRY_
{
	_LIST_ENTRY_<_Ty> InLoadOrderLinks;
	_LIST_ENTRY_<_Ty> InMemoryOrderLinks;
	_LIST_ENTRY_<_Ty> InInitializationOrderLinks;
	_Ty DllBase;
	_Ty EntryPoint;
	unsigned long SizeOfImage;
	_UNICODE_STRING_<_Ty> FullDllName;
	_UNICODE_STRING_<_Ty> BaseDllName;
	unsigned long Flags;
	unsigned short LoadCount;
	unsigned short TlsIndex;
	_LIST_ENTRY_<_Ty> HashLinks;
	unsigned long TimeDateStamp;
	_Ty EntryPointActivationContext;
	_Ty PatchInformation;
};
template<typename _Ty>
struct _PROCESS_BASIC_INFORMATION_
{
	NTSTATUS ExitStatus;
	ULONG    Reserved0;
	_Ty        PebBaseAddress;
	_Ty        AffinityMask;
	LONG     BasePriority;
	ULONG    Reserved1;
	_Ty        UniqueProcessId;
	_Ty        InheritedFromUniqueProcessId;
};

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
	IN HANDLE           ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID            ProcessInformation,
	IN ULONG            ProcessInformationLength,
	OUT PULONG           ReturnLength OPTIONAL);

typedef NTSTATUS(NTAPI* NtWow64QueryInformationProcess64_t)(
	IN  HANDLE ProcessHandle,
	IN  ULONG  ProcessInformationClass,
	OUT PVOID  ProcessInformation,
	IN  ULONG  ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

typedef NTSTATUS(NTAPI* NtWow64ReadVirtualMemory64_t)(
	IN  HANDLE   ProcessHandle,
	IN  ULONG64  BaseAddress,
	OUT PVOID    BufferData,
	IN  ULONG64  BufferLength,
	OUT PULONG64 ReturnLength OPTIONAL);

typedef
NTSTATUS(NTAPI* NtReadVirtualMemory_t)(

	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesReaded OPTIONAL);

class CCModule;

using module_collection_unique_ptr = std::unique_ptr<std::vector<CCModule>>;
using module_collection_ptr = std::vector<CCModule>*;

class CCDrvKit_ModuleEnumerator :
    public IDrvKit_Enumerator
{	
private:
	NtWow64ReadVirtualMemory64_t _pfnNtWow64ReadVirtualMemory64;
	NtReadVirtualMemory_t _pfnNtReadVirtualMemory;
	NtQueryInformationProcess_t _pfnNtQueryInformationProcess;
	NtWow64QueryInformationProcess64_t _pfnNtWow64QueryInformationProcess64;
	
protected:
	bool ReadRemoteMemory(HANDLE Prochandle, PVOID Dest, SIZE_T ReadBytes, ULONG Src);
	bool ReadRemoteMemory(HANDLE Prochandle, PVOID Dest, SIZE_T ReadBytes, ULONG64 Src);

	template<typename _Ty>
	ULONG64 GetPeb(HANDLE Prochandle, typename _PEB_T<_Ty>::type* Peb);

	template<typename _Ty>
	bool EnumModuleInfoByPeb(HANDLE ProcessHandle, module_collection_ptr ModInfoSet);
public:
	CCDrvKit_ModuleEnumerator();
	bool Enumerate(void* Param, uint32_t ProcessId = 0);
};

class CCModule
{
public:
	CCModule(ULONG64 BaseAddress, size_t ModuleSize, QString ModuleName, QString ModulePath);
	~CCModule();

	const QString& GetName()const;
	const QString& GetFullPath()const;
	const size_t GetSize()const;
	const ULONG64 GetBaseAddress()const;

protected:
	ULONG64 m_BaseAddr;
	size_t m_ModuleSize;
	QString m_ModuleName;
	QString m_ModulePath;
};



