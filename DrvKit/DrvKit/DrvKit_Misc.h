#pragma once
#include "prefix.h"
#include <vector>

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED        0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH      0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER      0x00000004

#define SEC_IMAGE 0x1000000

namespace DK
{
	typedef struct _QUERY_NAME_WORK_ITEM
	{
		WORK_QUEUE_ITEM WorkQueueItem;
		PUNICODE_STRING NtPath;
		PUNICODE_STRING DevicePath;
		KEVENT CompleteEvent;
		NTSTATUS  Status;
	} QUERY_NAME_WORK_ITEM, * PQUERY_NAME_WORK_ITEM;

	typedef struct _MODULE_INFO
	{
		PVOID LoadBaseAddress;
		SIZE_T ImageSize;
		WCHAR FullPath[MAX_PATH_SIZE];
	}MODULE_INFO,*PMODULE_INFO;

	class DrvKit_Misc
	{
	private:
		DrvKit_Misc();
		~DrvKit_Misc();

		static PVOID GetUserModuleBaseByProcessInternal(
			_In_ PEPROCESS Process,
			_In_ BOOLEAN IsWow64,
			_In_ PUNICODE_STRING ModuleName);

		static VOID DevicePathToNtPathWork(PQUERY_NAME_WORK_ITEM WorkItem);
		static NTSTATUS DevicePathToNtPathInternal(_In_ PUNICODE_STRING DevicePath, _Inout_ PUNICODE_STRING NtPath);
	public:
		static ULONG m_OsMajorNumber;
		static ULONG m_OsMinorNumber;
		static ULONG m_OsBuildNumber;

	public:
		static NTSTATUS Init();
		static BOOLEAN IsSystemSupported();
		static NTSTATUS AllocAndCopyUnicodeString(
			_Inout_ PUNICODE_STRING NewUnicodeString,
			_In_ PUNICODE_STRING UnicodeString);
		static VOID ReleaseUnicodeString(_In_ PUNICODE_STRING UnicodeString);
		static NTSTATUS LockAndAttachProcess(_In_ PEPROCESS Process,_Inout_ PKAPC_STATE ApcState);
		static VOID AttachProcess(_In_ PEPROCESS Process,_Inout_ PKAPC_STATE ApcState);
		static VOID UnLockAndDetachProcess(_In_ PEPROCESS Process,_In_ PKAPC_STATE ApcState);
		static VOID DetachProcess(_In_ PKAPC_STATE ApcState);
		static NTSTATUS SearchPattern(
			_In_ PCUCHAR pattern,
			_In_ UCHAR wildcard,
			_In_ ULONG_PTR len,
			_In_ const VOID* base,
			_In_ ULONG_PTR size,
			_Inout_ PVOID* ppFound);
		static PVOID AllocateUserMemory(HANDLE ProcessHandle, SIZE_T Size);
		static VOID ReleaseUserMemory(HANDLE ProcessHandle, PVOID Address,SIZE_T Size);
		static NTSTATUS WriteUserMemory(HANDLE ProcessHandle, PUCHAR Dest, PUCHAR Src, SIZE_T Size);
		static NTSTATUS ReadFromUserMemory(HANDLE ProcessHandle, PUCHAR Dest,PUCHAR Src,SIZE_T Size);
		static HANDLE CreateSectionByFile(UNICODE_STRING FilePath, BOOLEAN IsExecutable = TRUE);
		static HANDLE CreateEventForCurrentProcess();
		static HANDLE CreateUserThread(
			HANDLE ProcessHandle, 
			PVOID StartRoutine,
			PVOID Param, 
			BOOLEAN IsSuspend = FALSE);
		static PVOID GetUserModuleBaseByProcess(
			_In_ PEPROCESS Process, 
			_In_ BOOLEAN IsWow64,
			_In_ PWCHAR FullModuleName);
		static NTSTATUS OpenProcess(_Inout_ PHANDLE handle, _In_ ULONG Pid);
		static BOOLEAN IsWow64Process(HANDLE ProcessId);
		static NTSTATUS RetrievesAllModulesByProcessId(_In_ ULONG ProcessId, _Inout_ std::vector<MODULE_INFO>* ModulInfo);
		static NTSTATUS DevicePathToNtPath(_In_ PUNICODE_STRING DevicePath, _Inout_ PUNICODE_STRING NtPath);
		static NTSTATUS NtPathToDevicePath(_In_ PUNICODE_STRING NtPath, _Inout_ PUNICODE_STRING DevicePath);
	};
};