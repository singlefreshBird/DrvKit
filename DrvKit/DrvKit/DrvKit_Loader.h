#pragma once
#include "prefix.h"
#include "DrvKit_HookEng.h"
#include <vector>
#include <map>

#define NATIVE_NTDLL_PATH L"C:\\Windows\\System32\\ntdll.dll"
#define WOW64_NTDLL_PATH L"C:\\Windows\\SysWOW64\\ntdll.dll"


namespace DK
{
	// ‘› ±Œﬁ”√
	typedef enum _LAOD_TYPE
	{
		eLoadType_Unk = 0
	}LAOD_TYPE;

	typedef struct _LOAD_SHELLCODEX64
	{
		UCHAR Prologue[24];
		UCHAR GetCurrentTid[12];
		UCHAR OverWriteTidToNtCreateSection[9];
		UCHAR PassLoadArgument1[6];
		UCHAR PassModuleName[10];
		UCHAR PassLoadAddress[10];
		UCHAR CallLdrLoadRoutine[6];
		UCHAR SetStatus[6];
		UCHAR PassEventhandle[7];
		UCHAR PassSynArgument2[2];
		UCHAR CallSetEventRoutine[6];
		UCHAR SetComplete[7];
		UCHAR Epilogue[25];
	}LOAD_SHELLCODEX64,*PLOAD_SHELLCODEX64;

	typedef struct _LOAD_SHELLCODEX32
	{
		UCHAR Prologue[3];
		UCHAR GetCurrentTid[9];
		UCHAR OverWriteTidToNtCreateSection[5];
		UCHAR PassLoadAddress[5];
		UCHAR PassModuleName[5];
		UCHAR PassLoadRemain[4];
		UCHAR CallLdrLoadRoutine[6];
		UCHAR SetStatus[5];
		UCHAR PassSynArgument1[2];
		UCHAR PassEventHandle[5];
		UCHAR CallSetEventRoutine[6];
		UCHAR SetComplete[7];
		UCHAR Epilogue[2];
	}LOAD_SHELLCODEX32, * PLOAD_SHELLCODEX32;

	typedef struct _LOAD_PAYLOAD
	{
		struct
		{
			HANDLE Event;
			PVOID NtCreateSectionThread;
			PVOID SetEventRoutine;
			PVOID LdrLoadDllRoutine;
			PVOID LoadBaseAddress;
			BOOLEAN Complete;
			NTSTATUS Status;
			union
			{
				UNICODE_STRING64 DllPath64;
				UNICODE_STRING32 DllPath32;
			}P;
			WCHAR Buffer[0x100];
		}Data;

		union
		{
			LOAD_SHELLCODEX64 Shellcode64;
			LOAD_SHELLCODEX32 Shellcode32;
		}Code;

	}LOAD_PAYLOAD, * PLOAD_PAYLOAD;

	typedef struct _LDR_WORKER_ITEM
	{
		WORK_QUEUE_ITEM LdrQueuWorker;
		BOOLEAN Unload;
		BOOLEAN Force;
		KEVENT WaitEvent;
		ULONG ProcessId;
		PWCHAR DllPath;
		PVOID NtdllBase;
		PVOID LoadBaseAddress;
		LAOD_TYPE Type;
		NTSTATUS LdrStatus;
	}LDR_WORKER_ITEM,*PLDR_WORKER_ITEM;

	typedef struct _GARBAGE_ITEM
	{
		HANDLE ProcessId;
		PLOAD_PAYLOAD LdrPayload;
		DrvKit_HookEng* HookCreSecInst;
		DrvKit_HookEng* HookTesAltInst;
	}GARBAGE_ITEM,*PGARBAGE_ITEM;

	class DrvKit_Loader
	{
	private:
		static std::vector<PGARBAGE_ITEM>* m_Dustbin;
		static ERESOURCE m_DustbinRWLock;
		static BOOLEAN m_Shutdown;
		static BOOLEAN m_Inited;
	private:
		DrvKit_Loader();
		~DrvKit_Loader();
		
		static NTSTATUS LoadDllInternal(
			_In_ PEPROCESS Process, 
			_In_ PWCHAR DllPath, 
			_Inout_ PVOID* LoadBaseAddress,
			_In_opt_ PVOID NtdllBase = NULL);
		static VOID UnloadDllInternal(
			_In_ PEPROCESS Process,
			_Inout_ PVOID LoadBaseAddress,
			_In_ BOOLEAN ForceUnload = FALSE);
		static VOID GenLoadShellcode(_In_ BOOLEAN IsWow64,_Inout_ PLOAD_PAYLOAD Payload);
		static PLOAD_PAYLOAD PrepareLoadPayload(
			_In_ PEPROCESS Process,
			_In_ PWCHAR DllPath,
			_In_ BOOLEAN IsWow64,
			_In_ PVOID LoadRoutine,
			_In_ PVOID SetEventRoutine,
			_Inout_ PNT_CREATESECTION_PAYLOAD CreateSectionCode,
			_Inout_ PNT_TESTALERT_PAYLOAD TestAlertCode,
			_In_ BOOLEAN IsInjectPPL = FALSE);
		static VOID LdrThreadWorker(_In_ PVOID Parameter);
		static VOID GarbageCollect();
		static VOID ProcessCreateNotify(
			_In_ HANDLE ParentId,
			_In_ HANDLE ProcessId,
			_In_ BOOLEAN Create,
			_In_opt_ PBOOLEAN Next);
		static PVOID GetLoadedBaseAddress(HANDLE ProcessId, PWCHAR DllPath);
		static VOID ReleaseDustbin();
	public:
		static BOOLEAN Init();
		static VOID UnInit();
		static NTSTATUS LoadDll(
			_In_ ULONG ProcessId,
			_In_ PWCHAR DllPath,
			_Inout_ PVOID* LoadBaseAddress,
			_In_opt_ PVOID NtdllBase = NULL);
		static VOID UnLoadDll(
			_In_ ULONG ProcessId, 
			_Inout_ PVOID LoadBaseAddress,
			_In_ BOOLEAN ForceUnload=FALSE);
	};
};