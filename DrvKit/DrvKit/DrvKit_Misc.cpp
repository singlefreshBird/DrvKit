#include "DrvKit_Misc.h"
#include "DrvKit_FileMgmt.h"
#include "DrvKit_Private.h"
#include "DrvKit_BinaryAnalyze.h"
#include <ntstrsafe.h>

#define LDR_OFFSET_OF_PEB_X32 0xC
#define LDR_OFFSET_OF_PEB_X64 0x18

namespace DK
{
	ULONG DrvKit_Misc::m_OsMajorNumber = 0;
	ULONG DrvKit_Misc::m_OsMinorNumber = 0;
	ULONG DrvKit_Misc::m_OsBuildNumber = 0;
	
	DrvKit_Misc::DrvKit_Misc(){}
	DrvKit_Misc::~DrvKit_Misc(){}


	NTSTATUS DrvKit_Misc::Init()
	{
		RTL_OSVERSIONINFOW osVer;
		

		osVer.dwOSVersionInfoSize = sizeof(osVer);

		NTSTATUS ntStatus = RtlGetVersion(&osVer);
		if(!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("Filed to get system version.\n");
			goto end;
		}

		m_OsBuildNumber = osVer.dwBuildNumber;
		m_OsMajorNumber = osVer.dwMajorVersion;
		m_OsMinorNumber = osVer.dwMinorVersion;

		DrvKit_ReportInfo(
			"OS version: %d.%d.%d\n",
			m_OsMajorNumber,
			m_OsMinorNumber,
			m_OsBuildNumber
		);

	end:

		return ntStatus;
	}

	BOOLEAN DrvKit_Misc::IsSystemSupported()
	{
		// Win7 ~ Win11 20H3,理论上可以支持到最新Windows系统
		return m_OsBuildNumber >= 7600/* && m_OsBuildNumber <= 22631*/;
	}

	NTSTATUS DrvKit_Misc::AllocAndCopyUnicodeString(
		_Inout_ PUNICODE_STRING NewUnicodeString,
		_In_ PUNICODE_STRING UnicodeString)
	{
		PWCHAR pBuffer = NULL;

		if (NewUnicodeString == NULL || UnicodeString == NULL)
		{
			return STATUS_INVALID_PARAMETER;
		}

		pBuffer = new WCHAR[UnicodeString->MaximumLength];
		if (pBuffer == NULL)
		{
			DrvKit_ReportError("System resources insufficient.\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlCopyMemory(pBuffer, UnicodeString->Buffer, UnicodeString->MaximumLength);
		NewUnicodeString->Buffer = pBuffer;
		NewUnicodeString->Length = UnicodeString->Length;
		NewUnicodeString->MaximumLength = UnicodeString->MaximumLength;

		return STATUS_SUCCESS;
	}

	VOID DrvKit_Misc::ReleaseUnicodeString(_In_ PUNICODE_STRING UnicodeString)
	{
		if (UnicodeString)
		{
			if (UnicodeString->Buffer)
			{
				delete[] UnicodeString->Buffer;
				UnicodeString->Buffer = NULL;
			}

			UnicodeString->Length = 0;
			UnicodeString->MaximumLength = 0;
		}
	}

	NTSTATUS DrvKit_Misc::LockAndAttachProcess(_In_ PEPROCESS Process, _Inout_ PKAPC_STATE ApcState)
	{
		NTSTATUS ntStatus = PsAcquireProcessExitSynchronization(Process);
		if (NT_SUCCESS(ntStatus))
		{
			AttachProcess(Process, ApcState);
		}

		return ntStatus;
	}

	VOID DrvKit_Misc::AttachProcess(_In_ PEPROCESS Process, _Inout_ PKAPC_STATE ApcState)
	{
		KeStackAttachProcess(Process, ApcState);
	}

	VOID DrvKit_Misc::UnLockAndDetachProcess(_In_ PEPROCESS Process, _In_ PKAPC_STATE ApcState)
	{
		DetachProcess(ApcState);
		PsReleaseProcessExitSynchronization(Process);
	}

	VOID DrvKit_Misc::DetachProcess(_In_ PKAPC_STATE ApcState)
	{
		KeUnstackDetachProcess(ApcState);
	}

	NTSTATUS DrvKit_Misc::SearchPattern(
		_In_ PCUCHAR pattern,
		_In_ UCHAR wildcard,
		_In_ ULONG_PTR len,
		_In_ const VOID* base,
		_In_ ULONG_PTR size,
		_Inout_ PVOID* ppFound)
	{
		if (ppFound == NULL || pattern == NULL || base == NULL)
			return STATUS_INVALID_PARAMETER;

		for (ULONG_PTR i = 0; i < size - len; i++)
		{
			BOOLEAN found = TRUE;
			for (ULONG_PTR j = 0; j < len; j++)
			{
				if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
				{
					found = FALSE;
					break;
				}
			}

			if (found != FALSE)
			{
				*ppFound = (PUCHAR)base + i;
				return STATUS_SUCCESS;
			}
		}

		return STATUS_NOT_FOUND;
	}

	PVOID DrvKit_Misc::AllocateUserMemory(HANDLE ProcessHandle, SIZE_T Size)
	{
		PVOID pBuffer;
		HANDLE hSection = NULL;
		HANDLE hTargetProcess = NULL;
		OBJECT_ATTRIBUTES oa;
		LARGE_INTEGER MaxSize = { 0 };
		LARGE_INTEGER Offset = { 0 };
		PVOID pMapBaseAddress = NULL;
		NTSTATUS ntStatus;

		ntStatus = DrvKit_Private::m_pfnZwAllocateVirtualMemory(
			ProcessHandle, 
			&pMapBaseAddress,
			0, 
			&Size,
			MEM_COMMIT, 
			PAGE_EXECUTE_READWRITE);

		DrvKit_ReportInfo("Alloc memory result code: %I32x\n", ntStatus);

		return NT_SUCCESS(ntStatus) ? pMapBaseAddress : NULL;
	}

	VOID DrvKit_Misc::ReleaseUserMemory(HANDLE ProcessHandle, PVOID Address, SIZE_T Size)
	{
		DrvKit_Private::m_pfnZwFreeVirtualMemory(ProcessHandle, &Address, &Size, MEM_RELEASE);
	}

	NTSTATUS DrvKit_Misc::WriteUserMemory(
		HANDLE ProcessHandle,
		PUCHAR Dest,
		PUCHAR Src,
		SIZE_T Size)
	{
		SIZE_T szWritten;

		return DrvKit_Private::m_pfnZwWriteVirtualMemory(
			ProcessHandle,
			Dest,
			Src,
			Size,
			&szWritten);
	}

	NTSTATUS DrvKit_Misc::ReadFromUserMemory(HANDLE ProcessHandle, PUCHAR Dest, PUCHAR Src, SIZE_T Size)
	{
		ULONG szRead;
		return DrvKit_Private::m_pfnZwReadVirtualMemory(
			ProcessHandle,
			Dest,
			Src,
			Size,
			&szRead);
	}

	HANDLE DrvKit_Misc::CreateSectionByFile(UNICODE_STRING FilePath, BOOLEAN IsExecutable)
	{
		NTSTATUS ntStatus;
		HANDLE hSection = NULL;
		DrvKit_FileMgmt fileMgmt(FilePath);

		ntStatus = fileMgmt.Open(OPEN_EXIST, GENERIC_READ);
		if (NT_SUCCESS(ntStatus))
		{
			ntStatus = ZwCreateSection(
				&hSection,
				(IsExecutable ? SECTION_MAP_EXECUTE : 0 ) | SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ,
				NULL,
				NULL,
				PAGE_EXECUTE,
				0x1000000,
				fileMgmt.GetHandle());
			if (NT_SUCCESS(ntStatus))
			{
				return hSection;
			}
		}

		return NULL;
	}

	HANDLE DrvKit_Misc::CreateEventForCurrentProcess()
	{
		NTSTATUS ntStatus;
		OBJECT_ATTRIBUTES oa;
		HANDLE hEvent;

		InitializeObjectAttributes(&oa, NULL, NULL, NULL, NULL);
		ntStatus = ZwCreateEvent(
			&hEvent,
			EVENT_ALL_ACCESS,
			&oa,
			NotificationEvent,
			FALSE);

		return NT_SUCCESS(ntStatus) ? hEvent : NULL;
	}

	HANDLE DrvKit_Misc::CreateUserThread(
		HANDLE ProcessHandle, 
		PVOID StartRoutine, 
		PVOID Param, 
		BOOLEAN IsSuspend)
	{
		NTSTATUS ntStatus;
		HANDLE hThread = NULL;
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, NULL, NULL, NULL, NULL);

		ntStatus = DrvKit_Private::m_pfnZwCreateThreadEx(
			&hThread,
			THREAD_QUERY_LIMITED_INFORMATION,
			&oa,
			ProcessHandle,
			StartRoutine,
			Param,
			IsSuspend ? THREAD_CREATE_FLAGS_CREATE_SUSPENDED : 0,
			0,
			0x1000,
			0x100000,
			NULL);
		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("Failed to create thread -- Erro code: %I32x\n", ntStatus);
			return NULL;
		}

		return hThread;
	}

	PVOID DrvKit_Misc::GetUserModuleBaseByProcess(
		_In_ PEPROCESS Process,
		_In_ BOOLEAN IsWow64,
		_In_ PWCHAR FullModuleName)
	{
		UNICODE_STRING uzDesiredName;
		PVOID ptrDllBase = NULL;
		KAPC_STATE ApcStat;

		if (Process == NULL || FullModuleName == NULL) return NULL;

		RtlInitUnicodeString(&uzDesiredName, FullModuleName);
	
		if (PsGetCurrentProcess() != Process)
		{
			AttachProcess(Process, &ApcStat);

			ptrDllBase = GetUserModuleBaseByProcessInternal(Process, IsWow64, &uzDesiredName);

			DetachProcess(&ApcStat);
		}
		else
		{
			ptrDllBase = GetUserModuleBaseByProcessInternal(Process, IsWow64, &uzDesiredName);
		}

		return ptrDllBase;
	}

	PVOID DrvKit_Misc::GetUserModuleBaseByProcessInternal(
		_In_ PEPROCESS Process,
		_In_ BOOLEAN IsWow64,
		_In_ PUNICODE_STRING ModuleName)
	{
		PVOID pModuleBase = NULL;
		__try
		{
			if (IsWow64)
			{
				PPEB32 peb;
				PPEB_LDR_DATA32 ldrDataEnt32;
#ifdef _AMD64_
				peb = (PPEB32)PsGetProcessWow64Process(Process);
#else
				peb = (PPEB32)PsGetProcessPeb(Process);
#endif
				if (peb == NULL)
				{
					DrvKit_ReportError("Can't find Peb.\n");
					goto Exit;
				}

				ldrDataEnt32 = (PPEB_LDR_DATA32)peb->Ldr;

				if (ldrDataEnt32 == NULL)
				{
					DrvKit_ReportError("Haven't Module: %wZ.\n", ModuleName);
					goto Exit;
				}

				ProbeForRead(ldrDataEnt32, sizeof(PPEB_LDR_DATA32), 1);
				ProbeForRead((PVOID)ldrDataEnt32->InLoadOrderModuleList.Flink, sizeof(PLIST_ENTRY32), 1);
				ProbeForRead((PVOID)ldrDataEnt32->InLoadOrderModuleList.Blink, sizeof(PLIST_ENTRY32), 1);

				PLIST_ENTRY32 pListEnt = NULL;
				for (pListEnt = (PLIST_ENTRY32)ldrDataEnt32->InLoadOrderModuleList.Flink;
					pListEnt != (PLIST_ENTRY32)ldrDataEnt32->InLoadOrderModuleList.Blink;
					pListEnt = (PLIST_ENTRY32)pListEnt->Flink)
				{
					PLDR_DATA_TABLE_ENTRY32 pLdrDataTblEnt32;
					UNICODE_STRING uzCmpString;

					ProbeForRead(pListEnt, sizeof(PLIST_ENTRY32), 1);

					pLdrDataTblEnt32 = 
						CONTAINING_RECORD(
							pListEnt, 
							LDR_DATA_TABLE_ENTRY32, 
							InLoadOrderLinks);

					RtlInitUnicodeString(&uzCmpString, (PWCHAR)pLdrDataTblEnt32->FullDllName.Buffer);
					uzCmpString.Length = pLdrDataTblEnt32->FullDllName.Length;
					uzCmpString.MaximumLength = pLdrDataTblEnt32->FullDllName.MaximumLength;

					if (RtlCompareUnicodeString(&uzCmpString, ModuleName, TRUE) == 0)
					{
						pModuleBase = (PVOID)pLdrDataTblEnt32->DllBase;
						break;
					}
				}
			}
			else
			{
				PPEB peb = (PPEB)PsGetProcessPeb(Process);
				if (peb == NULL)
				{
					DrvKit_ReportError("Can't find Peb.\n");
					goto Exit;
				}

				PPEB_LDR_DATA ldrDataEnt = peb->Ldr;

				if (ldrDataEnt == NULL)
				{
					DrvKit_ReportError("Havn't Module.\n");
					goto Exit;
				}

				ProbeForRead(ldrDataEnt, sizeof(PPEB_LDR_DATA), 1);
				ProbeForRead((PVOID)ldrDataEnt->InLoadOrderModuleList.Flink, sizeof(PLIST_ENTRY), 1);
				ProbeForRead((PVOID)ldrDataEnt->InLoadOrderModuleList.Blink, sizeof(PLIST_ENTRY), 1);
				
				for (PLIST_ENTRY pListEnt = (PLIST_ENTRY)ldrDataEnt->InLoadOrderModuleList.Flink;
					pListEnt != (PLIST_ENTRY)ldrDataEnt->InLoadOrderModuleList.Blink;
					pListEnt = (PLIST_ENTRY)pListEnt->Flink)
				{
					PLDR_DATA_TABLE_ENTRY pLdrDataTblEnt;
					
					ProbeForRead(pListEnt, sizeof(PLIST_ENTRY), 1);

					pLdrDataTblEnt =
						CONTAINING_RECORD(
							pListEnt, 
							LDR_DATA_TABLE_ENTRY, 
							InLoadOrderLinks);

					if (RtlCompareUnicodeString(&pLdrDataTblEnt->FullDllName, ModuleName, TRUE) == 0)
					{
						pModuleBase = pLdrDataTblEnt->DllBase;
						break;
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DrvKit_ReportException(
				"An exception occurred -- Code: %I32x\n",
				GetExceptionCode());
		}
		
	Exit:
		return pModuleBase;

	}

	VOID DrvKit_Misc::DevicePathToNtPathWork(PQUERY_NAME_WORK_ITEM WorkItem)
	{
		WorkItem->Status = DevicePathToNtPathInternal(WorkItem->DevicePath, WorkItem->NtPath);
		KeSetEvent(&WorkItem->CompleteEvent, IO_NO_INCREMENT, FALSE);
	}

	NTSTATUS DrvKit_Misc::OpenProcess(_Inout_ PHANDLE handle, _In_ ULONG Pid)
	{
		OBJECT_ATTRIBUTES oa;
		CLIENT_ID cid = { 0 };
		cid.UniqueProcess = (HANDLE)Pid;

		InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

		return ZwOpenProcess(handle, GENERIC_ALL, &oa, &cid);
	}

	BOOLEAN DrvKit_Misc::IsWow64Process(HANDLE ProcessId)
	{
#ifdef _AMD64_
		BOOLEAN bIsWow64 = FALSE;
		if (PsGetCurrentProcessId() == ProcessId)
		{
			return PsGetCurrentProcessWow64Process() != NULL;
		}
		else
		{
			PEPROCESS pProcess;
			if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &pProcess)))
			{
				bIsWow64 = PsGetProcessWow64Process(pProcess) != NULL;
				ObDereferenceObject(pProcess);
			}

			return bIsWow64;
		}
#else
		return TRUE;
#endif
	}


	NTSTATUS DrvKit_Misc::DevicePathToNtPathInternal(_In_ PUNICODE_STRING DevicePath, _Inout_ PUNICODE_STRING NtPath)
	{
		NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
		HANDLE  hFile = NULL;
		OBJECT_ATTRIBUTES oa;
		PFILE_OBJECT pFileObj = NULL;
		IO_STATUS_BLOCK iostk;
		POBJECT_NAME_INFORMATION  pObjNameInfo = NULL;

		if (KeGetCurrentIrql() > PASSIVE_LEVEL) return ntStatus;

		InitializeObjectAttributes(&oa, DevicePath, OBJ_KERNEL_HANDLE, NULL, NULL);

		ntStatus = IoCreateFile(
			&hFile,
			FILE_READ_ATTRIBUTES,
			&oa,
			&iostk,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE,
			NULL,
			0,
			CreateFileTypeNone,
			NULL,
			IO_NO_PARAMETER_CHECKING);
		if (!NT_SUCCESS(ntStatus)) goto cleanup;

		ntStatus = ObReferenceObjectByHandle(hFile, FILE_ANY_ACCESS, *IoFileObjectType, KernelMode, (PVOID*)&pFileObj, NULL);
		if (!NT_SUCCESS(ntStatus)) goto cleanup;

		ntStatus = IoQueryFileDosDeviceName(pFileObj, &pObjNameInfo);
		if (!NT_SUCCESS(ntStatus)) goto cleanup;

		if (pObjNameInfo->Name.MaximumLength < MAX_PATH_SIZE * sizeof(WCHAR))
		{
			RtlCopyUnicodeString(NtPath, &pObjNameInfo->Name);
			ntStatus = STATUS_SUCCESS;
		}
		else
		{
			ntStatus = STATUS_BUFFER_OVERFLOW;
		}

	cleanup:
		if (pObjNameInfo) ExFreePool(pObjNameInfo);
		if (pFileObj) ObDereferenceObject(pFileObj);
		if (hFile) ZwClose(hFile);

		return ntStatus;

	}

	NTSTATUS DrvKit_Misc::DevicePathToNtPath(_In_ PUNICODE_STRING NtPath, _Inout_ PUNICODE_STRING DevicePath)
	{
		NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
		KIRQL kirpl = KeGetCurrentIrql();
		QUERY_NAME_WORK_ITEM Work;

		if (kirpl <= APC_LEVEL)
		{
			if (kirpl == APC_LEVEL)
			{
				KeInitializeEvent(&Work.CompleteEvent, NotificationEvent, FALSE);
				Work.NtPath = NtPath;
				Work.DevicePath = DevicePath;
				ExInitializeWorkItem(&Work.WorkQueueItem, (PWORKER_THREAD_ROUTINE)DevicePathToNtPathWork, &Work);
				ExQueueWorkItem(&Work.WorkQueueItem, DelayedWorkQueue);
				KeWaitForSingleObject(&Work.CompleteEvent, Executive, KernelMode, FALSE, NULL);
				ntStatus = Work.Status;
			}
			else
			{
				ntStatus = DevicePathToNtPathInternal(NtPath, DevicePath);
			}
		}

		return ntStatus;
	}

	NTSTATUS DrvKit_Misc::NtPathToDevicePath(_In_ PUNICODE_STRING NtPath, _Inout_ PUNICODE_STRING DevicePath)
	{
		HANDLE hFile = NULL;
		HANDLE hSym = NULL;
		NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
		const UNICODE_STRING usDir = RTL_CONSTANT_STRING(L"\\??");
		const WCHAR prefix[] = L"\\??\\";
		UNICODE_STRING usNtPath;
		OBJECT_ATTRIBUTES oa;
		WCHAR wzBuf[10] = {0};
		ULONG ulRetSize;

		InitializeObjectAttributes(&oa, (PUNICODE_STRING)&usDir, OBJ_CASE_INSENSITIVE, NULL, NULL);
		ntStatus = ZwOpenDirectoryObject(&hFile, FILE_READ_ACCESS, &oa);
		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("Failed to open directory object. Code = %I32X\n", ntStatus);
			goto cleanup;
		}

		*(wzBuf + 0) = NtPath->Buffer[0];
		*(wzBuf + 1) = NtPath->Buffer[1];

		RtlInitUnicodeString(&usNtPath, wzBuf);

		InitializeObjectAttributes(&oa, &usNtPath, OBJ_CASE_INSENSITIVE, hFile, NULL);
		ntStatus = ZwOpenSymbolicLinkObject(&hSym, FILE_READ_ACCESS, &oa);
		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("Failed to open symbolic link object: %wZ. Code = %I32X\n", usNtPath,ntStatus);
			goto cleanup;
		}

		ntStatus = ZwQuerySymbolicLinkObject(hSym, DevicePath, &ulRetSize);
		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("Failed to query symbolic link object. Code = %I32X\n", ntStatus);
		}

		if (DevicePath->Length + NtPath->MaximumLength < DevicePath->MaximumLength)
		{
			RtlUnicodeStringCatString(DevicePath, &NtPath->Buffer[2]);
		}
		else
		{
			ntStatus = STATUS_BUFFER_OVERFLOW;
		}

	cleanup:
		if (hFile) ZwClose(hFile);
		if (hSym) ZwClose(hSym);
		return ntStatus;
	}

	NTSTATUS DrvKit_Misc::RetrievesAllModulesByProcessId(_In_ ULONG ProcessId, _Inout_ std::vector<MODULE_INFO>* ModulInfo)
	{
		NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
		if (KeGetCurrentIrql() > APC_LEVEL) return ntStatus;

		HANDLE hProc = NULL;
		OBJECT_ATTRIBUTES oa;
		CLIENT_ID cid;
		MEMORY_BASIC_INFORMATION memInfo;
		SIZE_T cbLength;
		ULONG ulDelta = PAGE_SIZE;
		DrvKit_BinaryAnalyze bin(KernelMode);

		InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		cid.UniqueProcess = (HANDLE)ProcessId;
		cid.UniqueThread = 0;

		ntStatus = ZwOpenProcess(&hProc, GENERIC_ALL, &oa, &cid);
		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("Failed to open process.\n");
			goto cleanup;
		}

		for (ULONG_PTR StartAddress = 0; StartAddress < MmUserProbeAddress; StartAddress += ulDelta)
		{
			ntStatus = DrvKit_Private::m_pfnZwQueryVirtualMemory(
				hProc,
				(PVOID)StartAddress,
				MemoryBasicInformation,
				&memInfo,
				sizeof(memInfo),
				&cbLength);

			if (NT_SUCCESS(ntStatus) && memInfo.Type == SEC_IMAGE)
			{
				if (bin.LoadFromMap((PUCHAR)StartAddress))
				{
					ulDelta = bin.GetImageSize();

					MEMORY_SECTION_NAME memSecName;

					ntStatus = DrvKit_Private::m_pfnZwQueryVirtualMemory(
						hProc,
						(PVOID)StartAddress,
						MemorySectionName,
						&memSecName,
						sizeof(memSecName),
						&cbLength);

					if (NT_SUCCESS(ntStatus))
					{
						MODULE_INFO modInfo;

						modInfo.ImageSize = bin.GetImageSize();
						modInfo.LoadBaseAddress = (PVOID)StartAddress;
						RtlCopyMemory(modInfo.FullPath, memSecName.Buffer, sizeof(memSecName.Buffer));
						
						ModulInfo->push_back(modInfo);
					}
				}
				else
				{
					ulDelta = memInfo.RegionSize;
				}
			}
			else
			{
				ulDelta = PAGE_SIZE;
			}
		}


	cleanup:
		if (hProc) ZwClose(hProc);

		return ntStatus;

	}

};