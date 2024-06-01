#pragma once
#include <ntifs.h>
#include "DrvKit_Public.h"

#define DrvKit_ReportInfo(format,...)  \
do{ \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_INFO_LEVEL,"[+] "\
		format\
		,##__VA_ARGS__);\
}while(0)

#define DrvKit_ReportException(format,...)  \
do{ \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_TRACE_LEVEL,"[!](%I32X) %s:%d:%s() "\
		format \
	,GetExceptionCode(),__FILE__,__LINE__,__FUNCTION__,##__VA_ARGS__);\
}while(0)

#define DrvKit_ReportError(format,...)  \
do{ \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL,"[-] %s:%d:%s() "\
		format \
	,__FILE__,__LINE__,__FUNCTION__,##__VA_ARGS__);\
}while(0)


#define MAX(x,y) ((x)<(y)?(y):(x))

/*********************************************************枚举常量定义***********************************************************************************/
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0x00,
	SystemProcessorInformation = 0x01,
	SystemPerformanceInformation = 0x02,
	SystemTimeOfDayInformation = 0x03,
	SystemPathInformation = 0x04,
	SystemProcessAndThreadInformation = 0x05,
	SystemCallCountInformation = 0x06,
	SystemDeviceInformation = 0x07,
	SystemProcessorPerformanceInformation = 0x08,
	SystemFlagsInformation = 0x09,
	SystemCallTimeInformation = 0x0A,
	SystemModuleInformation = 0x0B,
	SystemLocksInformation = 0x0C,
	SystemStackTraceInformation = 0x0D,
	SystemPagedPoolInformation = 0x0E,
	SystemNonPagedPoolInformation = 0x0F,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1A,
	SystemUnloadGdiDriverInformation = 0x1B,
	SystemTimeAdjustmentInformation = 0x1C,
	SystemSummaryMemoryInformation = 0x1D,
	SystemMirrorMemoryInformation = 0x1E,
	SystemPerformanceTraceInformation = 0x1F,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2A,
	SystemLegacyDriverInformation = 0x2B,
	SystemCurrentTimeZoneInformation = 0x2C,
	SystemLookasideInformation = 0x2D,
	SystemTimeSlipNotification = 0x2E,
	SystemSessionCreate = 0x2F,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3A,
	SystemComPlusPackage = 0x3B,
	SystemNumaAvailableMemory = 0x3C,
	SystemProcessorPowerInformation = 0x3D,
	SystemEmulationBasicInformation = 0x3E,
	SystemEmulationProcessorInformation = 0x3F,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4A,
	SystemRegisterFirmwareTableInformationHandler = 0x4B,
	SystemFirmwareTableInformation = 0x4C,
	SystemModuleInformationEx = 0x4D,
	SystemVerifierTriageInformation = 0x4E,
	SystemSuperfetchInformation = 0x4F,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5A,
	SystemHypervisorInformation = 0x5B,
	SystemVerifierInformationEx = 0x5C,
	SystemTimeZoneInformation = 0x5D,
	SystemImageFileExecutionOptionsInformation = 0x5E,
	SystemCoverageInformation = 0x5F,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6A,
	SystemLogicalProcessorAndGroupInformation = 0x6B,
	SystemProcessorCycleTimeInformation = 0x6C,
	SystemStoreInformation = 0x6D,
	SystemRegistryAppendString = 0x6E,
	SystemAitSamplingValue = 0x6F,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7A,
	SystemBasicPerformanceInformation = 0x7B,
	SystemQueryPerformanceCounterInformation = 0x7C,
	SystemSessionBigPoolInformation = 0x7D,
	SystemBootGraphicsInformation = 0x7E,
	SystemScrubPhysicalMemoryInformation = 0x7F,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemPolicyInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8A,
	SystemMemoryChannelInformation = 0x8B,
	SystemBootLogoInformation = 0x8C,
	SystemProcessorPerformanceInformationEx = 0x8D,
	SystemCriticalProcessErrorLogInformation = 0x8E,
	SystemSecureBootPolicyInformation = 0x8F,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9A,
	SystemRegistryReconciliationInformation = 0x9B,
	SystemEdidInformation = 0x9C,
	SystemManufacturingInformation = 0x9D,
	SystemEnergyEstimationConfigInformation = 0x9E,
	SystemHypervisorDetailInformation = 0x9F,
	SystemProcessorCycleStatsInformation = 0xA0,
	SystemVmGenerationCountInformation = 0xA1,
	SystemTrustedPlatformModuleInformation = 0xA2,
	SystemKernelDebuggerFlags = 0xA3,
	SystemCodeIntegrityPolicyInformation = 0xA4,
	SystemIsolatedUserModeInformation = 0xA5,
	SystemHardwareSecurityTestInterfaceResultsInformation = 0xA6,
	SystemSingleModuleInformation = 0xA7,
	SystemAllowedCpuSetsInformation = 0xA8,
	SystemDmaProtectionInformation = 0xA9,
	SystemInterruptCpuSetsInformation = 0xAA,
	SystemSecureBootPolicyFullInformation = 0xAB,
	SystemCodeIntegrityPolicyFullInformation = 0xAC,
	SystemAffinitizedInterruptProcessorInformation = 0xAD,
	SystemRootSiloInformation = 0xAE,
	SystemCpuSetInformation = 0xAF,
	SystemCpuSetTagInformation = 0xB0,
	SystemWin32WerStartCallout = 0xB1,
	SystemSecureKernelProfileInformation = 0xB2,
	SystemCodeIntegrityPlatformManifestInformation = 0xB3,
	SystemInterruptSteeringInformation = 0xB4,
	SystemSuppportedProcessorArchitectures = 0xB5,
	SystemMemoryUsageInformation = 0xB6,
	SystemCodeIntegrityCertificateInformation = 0xB7,
	SystemPhysicalMemoryInformation = 0xB8,
	SystemControlFlowTransition = 0xB9,
	SystemKernelDebuggingAllowed = 0xBA,
	SystemActivityModerationExeState = 0xBB,
	SystemActivityModerationUserSettings = 0xBC,
	SystemCodeIntegrityPoliciesFullInformation = 0xBD,
	SystemCodeIntegrityUnlockInformation = 0xBE,
	SystemIntegrityQuotaInformation = 0xBF,
	SystemFlushInformation = 0xC0,
	SystemProcessorIdleMaskInformation = 0xC1,
	SystemSecureDumpEncryptionInformation = 0xC2,
	SystemWriteConstraintInformation = 0xC3,
	SystemKernelVaShadowInformation = 0xC4,
	SystemHypervisorSharedPageInformation = 0xC5,
	SystemFirmwareBootPerformanceInformation = 0xC6,
	SystemCodeIntegrityVerificationInformation = 0xC7,
	SystemFirmwarePartitionInformation = 0xC8,
	SystemSpeculationControlInformation = 0xC9,
	SystemDmaGuardPolicyInformation = 0xCA,
	SystemEnclaveLaunchControlInformation = 0xCB,
	SystemWorkloadAllowedCpuSetsInformation = 0xCC,
	SystemCodeIntegrityUnlockModeInformation = 0xCD,
	SystemLeapSecondInformation = 0xCE,
	SystemFlags2Information = 0xCF,
	SystemSecurityModelInformation = 0xD0,
	SystemCodeIntegritySyntheticCacheInformation = 0xD1,
	MaxSystemInfoClass = 0xD2
}SYSTEM_INFORMATION_CLASS;
/************************************************************END***************************************************************************************/


/**********************************************************导出函数定义***************************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif
	NTSYSAPI
		::PPEB
		NTAPI
		PsGetProcessPeb(_In_ PEPROCESS Process);

	NTSYSAPI
		PVOID
		NTAPI
		PsGetThreadTeb(_In_ PETHREAD Thread);

	NTSYSAPI
		PVOID
		NTAPI
		PsGetProcessWow64Process(_In_ PEPROCESS Process);

	NTSYSAPI
		PVOID
		NTAPI
		PsGetCurrentProcessWow64Process();

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwQuerySystemInformation(
			_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
			_Inout_ PVOID SystemInformation,
			_In_ ULONG SystemInformationLength,
			_Inout_ PULONG ReturnLength OPTIONAL
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwSetSystemInformation(
			_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
			_In_ PVOID SystemInformation,
			_In_ ULONG SystemInformationLength
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwQueryInformationProcess(
			_In_  HANDLE ProcessHandle,
			_In_  PROCESSINFOCLASS ProcessInformationClass,
			_Inout_ PVOID ProcessInformation,
			_In_  ULONG ProcessInformationLength,
			_In_  PULONG ReturnLength
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwQueryInformationThread(
			_In_ HANDLE ThreadHandle,
			_In_ THREADINFOCLASS ThreadInformationClass,
			_Inout_ PVOID ThreadInformation,
			_In_ ULONG ThreadInformationLength,
			_Inout_ PULONG ReturnLength
		);

	NTSYSAPI
		BOOLEAN
		NTAPI
		PsIsProtectedProcess(_In_ PEPROCESS Process);

	NTSYSAPI
		PIMAGE_NT_HEADERS
		NTAPI
		RtlImageNtHeader(PVOID Base);

	NTSYSAPI
		PVOID
		NTAPI
		RtlImageDirectoryEntryToData(
			PVOID BaseAddress,
			BOOLEAN MappedAsImage,
			USHORT Directory,
			PULONG Size);

	NTSYSAPI
		PVOID
		NTAPI
		RtlImageDirectoryEntryToData(
			PVOID ImageBase,
			BOOLEAN MappedAsImage,
			USHORT DirectoryEntry,
			PULONG Size
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		PsAcquireProcessExitSynchronization(PEPROCESS Process);

	NTSYSAPI
		VOID
		NTAPI
		PsReleaseProcessExitSynchronization(PEPROCESS Process);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwSetInformationProcess(
			HANDLE ProcessHandle,
			PROCESSINFOCLASS ProcessInformationClass,
			PVOID ProcessInformation,
			ULONG ProcessInformationLength);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwProtectVirtualMemory(
			HANDLE ProcessHandle,
			PVOID* BaseAddress,
			SIZE_T* NumberOfBytesToProtect,
			ULONG NewAccessProtection,
			PULONG OldAccessProtection);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwWriteVirtualMemory(
			HANDLE ProcessHandle,
			PVOID BaseAddress,
			PVOID Buffer,
			SIZE_T NumberOfBytesToWrite,
			PSIZE_T NumberOfBytesWritten);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwFlushInstructionCache(
			HANDLE ProcessHandle,
			PVOID BaseAddress,
			SIZE_T FlushSize);

#ifdef __cplusplus
}
#endif

#define POOL_TAG 'DjTk'

/************************************************************END***************************************************************************************/

/**********************************************************结构体定义***************************************************************************************/
#pragma warning(default : 4214)

namespace DK
{
	//0x8 bytes (sizeof)
	typedef struct _CLIENT_ID32
	{
		ULONG UniqueProcess;                                                    //0x0
		ULONG UniqueThread;                                                     //0x4
	}CLIENT_ID32,*PCLIENT_ID32;

	typedef struct _PEB_LDR_DATA
	{
		ULONG Length;
		UCHAR Initialized;
		PVOID SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct _LDR_DATA_TABLE_ENTRY
	{
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
		LIST_ENTRY HashLinks;
		ULONG TimeDateStamp;
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


	typedef struct _PEB_LDR_DATA32
	{
		ULONG Length;
		UCHAR Initialized;
		ULONG SsHandle;
		LIST_ENTRY32 InLoadOrderModuleList;
		LIST_ENTRY32 InMemoryOrderModuleList;
		LIST_ENTRY32 InInitializationOrderModuleList;
	} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

	typedef struct _LDR_DATA_TABLE_ENTRY32
	{
		LIST_ENTRY32 InLoadOrderLinks;
		LIST_ENTRY32 InMemoryOrderLinks;
		LIST_ENTRY32 InInitializationOrderLinks;
		ULONG DllBase;
		ULONG EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING32 FullDllName;
		UNICODE_STRING32 BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT TlsIndex;
		LIST_ENTRY32 HashLinks;
		ULONG TimeDateStamp;
	} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

#pragma warning(default : 4214)

	typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY
	{
		ULONG Attribute;    // PROC_THREAD_ATTRIBUTE_XXX
		SIZE_T Size;
		ULONG_PTR Value;
		ULONG Unknown;
	} NT_PROC_THREAD_ATTRIBUTE_ENTRY, * NT_PPROC_THREAD_ATTRIBUTE_ENTRY;

	typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST
	{
		ULONG Length;
		NT_PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
	} NT_PROC_THREAD_ATTRIBUTE_LIST, * PNT_PROC_THREAD_ATTRIBUTE_LIST;

	typedef struct _SYSTEM_THREAD_INFORMATION {
		LARGE_INTEGER Reserved1[3];
		ULONG Reserved2;
		PVOID StartAddress;
		CLIENT_ID ClientId;
		KPRIORITY Priority;
		LONG BasePriority;
		ULONG Reserved3;
		ULONG ThreadState;
		ULONG WaitReason;
	} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

	typedef struct _SYSTEM_PROCESS_INFORMATION {
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		UCHAR Reserved1[48];
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		PVOID Reserved2;
		ULONG HandleCount;
		ULONG SessionId;
		PVOID Reserved3;
		SIZE_T PeakVirtualSize;
		SIZE_T VirtualSize;
		ULONG Reserved4;
		SIZE_T PeakWorkingSetSize;
		SIZE_T WorkingSetSize;
		PVOID Reserved5;
		SIZE_T QuotaPagedPoolUsage;
		PVOID Reserved6;
		SIZE_T QuotaNonPagedPoolUsage;
		SIZE_T PagefileUsage;
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER Reserved7[6];
		SYSTEM_THREAD_INFORMATION Threads[1];
	} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

	typedef struct _RTL_SYSTEM_MODULE_INFORMATION
	{
		PVOID Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT ModuleNameOffset;
		CHAR FullPathName[256];
	}RTL_SYSTEM_MODULE_INFORMATION, * PRTL_SYSTEM_MODULE_INFORMATION;

	typedef struct  _RTL_SYSTEM_MODULES
	{
		ULONG NumberOfModules;
		RTL_SYSTEM_MODULE_INFORMATION Modules[ANYSIZE_ARRAY];
	}RTL_SYSTEM_MODULES, * PRTL_SYSTEM_MODULES;

	typedef struct _THREAD_BASIC_INFORMATION
	{
		NTSTATUS ExitStatus;
		PVOID TebBaseAddress;
		CLIENT_ID ClientId;
		ULONG_PTR AffinityMask;
		LONG Priority;
		LONG BasePriority;
	} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

	typedef struct _PEB
	{
		UCHAR InheritedAddressSpace;                                            //0x0
		UCHAR ReadImageFileExecOptions;                                         //0x1
		UCHAR BeingDebugged;                                                    //0x2
		union
		{
			UCHAR BitField;                                                     //0x3
			struct
			{
				UCHAR ImageUsesLargePages : 1;                                    //0x3
				UCHAR IsProtectedProcess : 1;                                     //0x3
				UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
				UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
				UCHAR IsPackagedProcess : 1;                                      //0x3
				UCHAR IsAppContainer : 1;                                         //0x3
				UCHAR IsProtectedProcessLight : 1;                                //0x3
				UCHAR IsLongPathAwareProcess : 1;                                 //0x3
			};
		};
		UCHAR Padding0[4];                                                      //0x4
		VOID* Mutant;                                                           //0x8
		VOID* ImageBaseAddress;                                                 //0x10
		PEB_LDR_DATA* Ldr;                                              //0x18
		struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
		VOID* SubSystemData;                                                    //0x28
		VOID* ProcessHeap;                                                      //0x30
		struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
		union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
		VOID* IFEOKey;                                                          //0x48
		union
		{
			ULONG CrossProcessFlags;                                            //0x50
			struct
			{
				ULONG ProcessInJob : 1;                                           //0x50
				ULONG ProcessInitializing : 1;                                    //0x50
				ULONG ProcessUsingVEH : 1;                                        //0x50
				ULONG ProcessUsingVCH : 1;                                        //0x50
				ULONG ProcessUsingFTH : 1;                                        //0x50
				ULONG ProcessPreviouslyThrottled : 1;                             //0x50
				ULONG ProcessCurrentlyThrottled : 1;                              //0x50
				ULONG ProcessImagesHotPatched : 1;                                //0x50
				ULONG ReservedBits0 : 24;                                         //0x50
			};
		};
		// ...
	}PEB, * PPEB;

	typedef struct _PEB32
	{
		UCHAR InheritedAddressSpace;                                            //0x0
		UCHAR ReadImageFileExecOptions;                                         //0x1
		UCHAR BeingDebugged;                                                    //0x2
		union
		{
			UCHAR BitField;                                                     //0x3
			struct
			{
				UCHAR ImageUsesLargePages : 1;                                    //0x3
				UCHAR IsProtectedProcess : 1;                                     //0x3
				UCHAR IsLegacyProcess : 1;                                        //0x3
				UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
				UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
				UCHAR SpareBits : 3;                                              //0x3
			};
		};
		ULONG Mutant;                                                           //0x4
		ULONG ImageBaseAddress;                                                 //0x8
		ULONG Ldr;                                                              //0xc
		ULONG ProcessParameters;                                                //0x10
		// ...
	}PEB32, * PPEB32;


	typedef enum _EXCEPTION_DISPOSITION
	{
		ExceptionContinueExecution = 0,
		ExceptionContinueSearch = 1,
		ExceptionNestedException = 2,
		ExceptionCollidedUnwind = 3
	}EXCEPTION_DISPOSITION;

	typedef struct _EXCEPTION_REGISTRATION_RECORD
	{
		struct _EXCEPTION_REGISTRATION_RECORD* Next;                            //0x0
		enum _EXCEPTION_DISPOSITION(*Handler)(struct _EXCEPTION_RECORD* arg1, VOID* arg2, struct _CONTEXT* arg3, VOID* arg4); //0x8
	}EXCEPTION_REGISTRATION_RECORD, * PEXCEPTION_REGISTRATION_RECORD;

	typedef struct _NT_TIB
	{
		struct _EXCEPTION_REGISTRATION_RECORD* ExceptionList;                   //0x0
		VOID* StackBase;                                                        //0x8
		VOID* StackLimit;                                                       //0x10
		VOID* SubSystemTib;                                                     //0x18
		union
		{
			VOID* FiberData;                                                    //0x20
			ULONG Version;                                                      //0x20
		};
		VOID* ArbitraryUserPointer;                                             //0x28
		struct _NT_TIB* Self;                                                   //0x30
	}NT_TIB, * PNT_TIB;

	//0x1c bytes (sizeof)
	typedef struct _NT_TIB32
	{
		ULONG ExceptionList;                                                    //0x0
		ULONG StackBase;                                                        //0x4
		ULONG StackLimit;                                                       //0x8
		ULONG SubSystemTib;                                                     //0xc
		union
		{
			ULONG FiberData;                                                    //0x10
			ULONG Version;                                                      //0x10
		};
		ULONG ArbitraryUserPointer;                                             //0x14
		ULONG Self;                                                             //0x18
	}NT_TIB32, * PNT_TIB32;

	struct _TEB
	{
		struct _NT_TIB NtTib;                                                   //0x0
		VOID* EnvironmentPointer;                                               //0x38
		struct _CLIENT_ID ClientId;                                             //0x40
		VOID* ActiveRpcHandle;                                                  //0x50
		VOID* ThreadLocalStoragePointer;                                        //0x58
		struct _PEB* ProcessEnvironmentBlock;                                   //0x60
		ULONG LastErrorValue;                                                   //0x68
		ULONG CountOfOwnedCriticalSections;                                     //0x6c
		VOID* CsrClientThread;                                                  //0x70
		VOID* Win32ThreadInfo;                                                  //0x78
	};

	typedef struct _TEB32
	{
		struct _NT_TIB32 NtTib;                                                 //0x0
		ULONG EnvironmentPointer;                                               //0x1c
		CLIENT_ID32 ClientId;                                           //0x20
		ULONG ActiveRpcHandle;                                                  //0x28
		ULONG ThreadLocalStoragePointer;                                        //0x2c
		ULONG ProcessEnvironmentBlock;                                          //0x30
		ULONG LastErrorValue;                                                   //0x34
		ULONG CountOfOwnedCriticalSections;                                     //0x38
		ULONG CsrClientThread;                                                  //0x3c
		ULONG Win32ThreadInfo;                                                  //0x40
	}TEB32, * PTEB32;

	typedef struct _MEMORY_BASIC_INFORMATION 
	{
		PVOID       BaseAddress;           //查询内存块所占的第一个页面基地址
		PVOID       AllocationBase;        //内存块所占的第一块区域基地址，小于等于BaseAddress，
		ULONG       AllocationProtect;     //区域被初次保留时赋予的保护属性
		SIZE_T      RegionSize;            //从BaseAddress开始，具有相同属性的页面的大小，
		ULONG       State;                 //页面的状态，有三种可能值MEM_COMMIT、MEM_FREE和MEM_RESERVE
		ULONG       Protect;               //页面的属性，其可能的取值与AllocationProtect相同
		ULONG       Type;                  //该内存块的类型，有三种可能值：MEM_IMAGE、MEM_MAPPED和MEM_PRIVATE
	} MEMORY_BASIC_INFORMATION, * PMEMORY_BASIC_INFORMATION;

	//MemorySectionName 
	typedef struct _MEMORY_SECTION_NAME 
	{
		UNICODE_STRING Name;
		WCHAR     Buffer[260];
	}MEMORY_SECTION_NAME, * PMEMORY_SECTION_NAME;

	typedef enum _MEMORY_INFORMATION_CLASS
	{
		MemoryBasicInformation = 0x0,
		MemoryWorkingSetList = 0x1,
		MemorySectionName = 0x2,
		MemoryBasicVlmInformation = 0x3,
		MemoryWorkingSetExList = 0x4
	}MEMORY_INFORMATION_CLASS;


};

/************************************************************END***************************************************************************************/

/*********************************************************系统函数原型定义***************************************************************************************/
typedef NTSTATUS(NTAPI* ZwSetInformationProcess_t)(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_In_ PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength);

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_In_ PVOID    SystemInformation,
	_In_ ULONG   SystemInformationLength,
	_Out_ PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI* NtTerminateProcess_t)(
	_In_ HANDLE ProcessHandle,
	_In_ NTSTATUS ExitStatus);

typedef NTSTATUS(NTAPI* NtOpenProcess_t)(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId);


typedef NTSTATUS(NTAPI* NtOpenThread_t)(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId);

typedef NTSTATUS(NTAPI* ZwCreateThreadEx_t)(
	_Inout_ PHANDLE hThread,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ PVOID ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID lpStartAddress,
	_In_ PVOID lpParameter,
	_In_ ULONG Flags,
	_In_ SIZE_T StackZeroBits,
	_In_ SIZE_T SizeOfStackCommit,
	_In_ SIZE_T SizeOfStackReserve,
	_Inout_ PVOID lpBytesBuffer);

typedef NTSTATUS(NTAPI* ZwProtectVirtualMemory_t)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_In_ PSIZE_T NumberOfBytesToProtect,
	_In_ ULONG NewAccessProtection,
	_Inout_ PULONG OldAccessProtection);

typedef NTSTATUS(NTAPI* ZwResumeThread_t)(
	_In_ HANDLE ThreadHandle,
	_Inout_ PULONG SuspendCount);

typedef NTSTATUS(NTAPI* ZwAllocateVirtualMemory_t)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect);

typedef NTSTATUS(NTAPI* ZwWriteVirtualMemory_t)(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ PVOID Buffer,
	_In_ SIZE_T NumberOfBytesToWrite,
	_Out_ PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS(NTAPI* ZwReadVirtualMemory_t)(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_Out_ PVOID Buffer,
	_In_ ULONG NumberOfBytesToRead,
	_Out_opt_ PULONG NumberOfBytesReaded);

typedef NTSTATUS(NTAPI* ZwFreeVirtualMemory_t)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG FreeType);

typedef NTSTATUS(NTAPI* ZwFlushInstructionCache_t)(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ SIZE_T FlushSize);

typedef BOOLEAN(__stdcall* DllEntryPoint_t)(
	PVOID hinstDLL,
	ULONG fdwReason,
	PVOID lpReserved);

typedef NTSTATUS(__fastcall* LdrUnloadDll_t)(PVOID LoadBaseAddress);

typedef NTSTATUS(NTAPI* ZwTerminateThread_t)(_In_ HANDLE ThreadHandle, _In_ NTSTATUS ExitStatus);


typedef NTSTATUS(NTAPI* ZwQueryVirtualMemory_t)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	DK::MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID MemoryInformation,
	SIZE_T MemoryInformationLength,
	PSIZE_T ReturnLength);

/************************************************************END***************************************************************************************/
