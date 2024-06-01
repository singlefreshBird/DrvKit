#include "DrvKit_Loader.h"
#include "DrvKit_Misc.h"
#include "DrvKit_UserCall.h"
#include "DrvKit_BinaryAnalyze.h"
#include "DrvKit_FileMgmt.h"
#include "DrvKit_Mitigation.h"
#include "DrvKit_Notify.h"

namespace DK
{
	std::vector<PGARBAGE_ITEM>* DrvKit_Loader::m_Dustbin = NULL;
	ERESOURCE DrvKit_Loader::m_DustbinRWLock;
	BOOLEAN DrvKit_Loader::m_Shutdown = FALSE;
	BOOLEAN DrvKit_Loader::m_Inited = FALSE;

	DrvKit_Loader::DrvKit_Loader(){}

	DrvKit_Loader::~DrvKit_Loader(){}

	BOOLEAN DrvKit_Loader::Init()
	{
		if (InterlockedAnd8((char*)&m_Inited, TRUE)) return TRUE;

		NTSTATUS ntStatus = ExInitializeResourceLite(&m_DustbinRWLock);
		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("Failed to init RWLock. Code = %I32X\n", ntStatus);
			goto cleanup;
		}

		/*ntStatus = DrvKit_Notify::RegisterProcessCreateNotify(ProcessCreateNotify);
		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("Failed to register Process creating notify. Code = %I32X\n", ntStatus);
			goto cleanup;
		}*/

		m_Dustbin = new std::vector<PGARBAGE_ITEM>;
		if (m_Dustbin == NULL) goto cleanup;

		m_Inited = TRUE;

	cleanup:
		if (!m_Inited)
		{
			if (m_Dustbin)
			{
				delete m_Dustbin;
				m_Dustbin = NULL;
			}
		}
		return TRUE;
	}

	VOID DrvKit_Loader::UnInit()
	{
		
		if (InterlockedExchange8((char*)&m_Inited, FALSE))
		{
			InterlockedExchange8((char*)&m_Shutdown, TRUE);

			ReleaseDustbin();

			//DrvKit_Notify::DegisterProcessCreateNotify(ProcessCreateNotify);

			ExDeleteResourceLite(&m_DustbinRWLock);
		}
	}

	VOID DrvKit_Loader::GenLoadShellcode(_In_ BOOLEAN IsWow64, _Inout_ PLOAD_PAYLOAD Payload)
	{
		if (IsWow64)
		{
			Payload->Code.Shellcode32.Prologue[0] = 0x55;
			Payload->Code.Shellcode32.Prologue[1] = 0x89;
			Payload->Code.Shellcode32.Prologue[2] = 0xE5;

			RtlCopyMemory(
				Payload->Code.Shellcode32.GetCurrentTid,
				"\x64\xA1\x18\x00\x00\x00\x8B\x40\x24",
				9);

			Payload->Code.Shellcode32.OverWriteTidToNtCreateSection[0] = 0xA3;
			*(PULONG)(Payload->Code.Shellcode32.OverWriteTidToNtCreateSection + 1) =
				(ULONG)Payload->Data.NtCreateSectionThread;

			Payload->Code.Shellcode32.PassLoadAddress[0] = 0x68;
			*(PLONG)(Payload->Code.Shellcode32.PassLoadAddress + 1) =
				(LONG)&Payload->Data.LoadBaseAddress;

			Payload->Code.Shellcode32.PassModuleName[0] = 0x68;
			*(PLONG)(Payload->Code.Shellcode32.PassModuleName + 1) =
				(LONG)&Payload->Data.P.DllPath32;

			RtlCopyMemory(
				Payload->Code.Shellcode32.PassLoadRemain,
				"\x6A\x00\x6A\x00",
				4);

			Payload->Code.Shellcode32.CallLdrLoadRoutine[0] = 0xFF;
			Payload->Code.Shellcode32.CallLdrLoadRoutine[1] = 0x15;
			*(PULONG)(Payload->Code.Shellcode32.CallLdrLoadRoutine + 2) =
				(ULONG)&Payload->Data.LdrLoadDllRoutine;

			Payload->Code.Shellcode32.SetComplete[0] = 0xC6;
			Payload->Code.Shellcode32.SetComplete[1] = 0x05;
			*(PULONG)(Payload->Code.Shellcode32.SetComplete + 2) =
				(ULONG)&Payload->Data.Complete;
			Payload->Code.Shellcode32.SetComplete[6] = 0x1;

			Payload->Code.Shellcode32.SetStatus[0] = 0xA3;
			*(PULONG)(Payload->Code.Shellcode32.SetStatus + 1) =
				(ULONG)&Payload->Data.Status;

			Payload->Code.Shellcode32.PassSynArgument1[0] = 0x6A;
			Payload->Code.Shellcode32.PassSynArgument1[1] = 0x00;
			Payload->Code.Shellcode32.PassEventHandle[0] = 0x68;
			*(PULONG)(Payload->Code.Shellcode32.PassEventHandle + 1) =
				(ULONG)Payload->Data.Event;

			Payload->Code.Shellcode32.CallSetEventRoutine[0] = 0xFF;
			Payload->Code.Shellcode32.CallSetEventRoutine[1] = 0x15;
			*(PULONG)(Payload->Code.Shellcode32.CallSetEventRoutine + 2) =
				(ULONG)&Payload->Data.SetEventRoutine;

			Payload->Code.Shellcode32.Epilogue[0] = 0xC9;
			Payload->Code.Shellcode32.Epilogue[1] = 0xC3;
		}
		else
		{
			RtlCopyMemory(
				Payload->Code.Shellcode64.Prologue,
				"\x48\x83\xec\x30\x48\x89\x4c\x24\x08"
				"\x48\x89\x54\x24\x10\x4c\x89\x44\x24"
				"\x18\x4c\x89\x4c\x24\x20",
				24);

			RtlCopyMemory(
				Payload->Code.Shellcode64.GetCurrentTid,
				"\x65\x48\x8B\x04\x25\x30\x00\x00\x00\x8B\x40\x48",
				12);

			Payload->Code.Shellcode64.OverWriteTidToNtCreateSection[0] = 0xA3;
			*(PULONG64)(Payload->Code.Shellcode64.OverWriteTidToNtCreateSection + 1) =
				(LONG64)Payload->Data.NtCreateSectionThread;

			RtlCopyMemory(
				Payload->Code.Shellcode64.PassLoadArgument1,
				"\x48\x31\xc9\x48\x31\xd2",
				6);
			Payload->Code.Shellcode64.PassModuleName[0] = 0x49;
			Payload->Code.Shellcode64.PassModuleName[1] = 0xB8;
			*(PULONG64)(Payload->Code.Shellcode64.PassModuleName + 2) =
				(ULONG64)&Payload->Data.P.DllPath64;

			Payload->Code.Shellcode64.PassLoadAddress[0] = 0x49;
			Payload->Code.Shellcode64.PassLoadAddress[1] = 0xB9;
			*(PULONG64)(Payload->Code.Shellcode64.PassLoadAddress + 2) =
				(ULONG64)&Payload->Data.LoadBaseAddress;

			Payload->Code.Shellcode64.CallLdrLoadRoutine[0] = 0xFF;
			Payload->Code.Shellcode64.CallLdrLoadRoutine[1] = 0x15;
			*(PLONG)(Payload->Code.Shellcode64.CallLdrLoadRoutine + 2) =
				(LONG64)&Payload->Data.LdrLoadDllRoutine -
				(LONG64)Payload->Code.Shellcode64.CallLdrLoadRoutine -
				sizeof(Payload->Code.Shellcode64.CallLdrLoadRoutine);

			Payload->Code.Shellcode64.SetComplete[0] = 0xC6;
			Payload->Code.Shellcode64.SetComplete[1] = 0x05;
			Payload->Code.Shellcode64.SetComplete[6] = 0x01;
			*(PLONG)(Payload->Code.Shellcode64.SetComplete + 2) =
				(LONG64)&Payload->Data.Complete -
				(LONG64)Payload->Code.Shellcode64.SetComplete -
				sizeof(Payload->Code.Shellcode64.SetComplete);

			Payload->Code.Shellcode64.SetStatus[0] = 0x89;
			Payload->Code.Shellcode64.SetStatus[1] = 0x05;
			*(PLONG)(Payload->Code.Shellcode64.SetStatus + 2) =
				(LONG64)&Payload->Data.Status -
				(LONG64)Payload->Code.Shellcode64.SetStatus -
				sizeof(Payload->Code.Shellcode64.SetStatus);

			Payload->Code.Shellcode64.PassEventhandle[0] = 0x48;
			Payload->Code.Shellcode64.PassEventhandle[1] = 0x8B;
			Payload->Code.Shellcode64.PassEventhandle[2] = 0x0D;
			*(PLONG)(Payload->Code.Shellcode64.PassEventhandle + 3) =
				(LONG64)&Payload->Data.Event -
				(LONG64)Payload->Code.Shellcode64.PassEventhandle -
				sizeof(Payload->Code.Shellcode64.PassEventhandle);

			Payload->Code.Shellcode64.PassSynArgument2[0] = 0x33;
			Payload->Code.Shellcode64.PassSynArgument2[1] = 0xD2;

			Payload->Code.Shellcode64.CallSetEventRoutine[0] = 0xFF;
			Payload->Code.Shellcode64.CallSetEventRoutine[1] = 0x15;
			*(PLONG)(Payload->Code.Shellcode64.CallSetEventRoutine + 2) =
				(LONG64)&Payload->Data.SetEventRoutine -
				(LONG64)Payload->Code.Shellcode64.CallSetEventRoutine -
				sizeof(Payload->Code.Shellcode64.CallSetEventRoutine);

			RtlCopyMemory(
				Payload->Code.Shellcode64.Epilogue,
				"\x48\x8b\x4c\x24\x08\x48\x8b\x54\x24"
				"\x10\x4c\x8b\x44\x24\x18\x4c\x8b\x4c"
				"\x24\x20\x48\x83\xc4\x30\xC3",
				25);
		}
	}

	PLOAD_PAYLOAD DrvKit_Loader::PrepareLoadPayload(
		_In_ PEPROCESS Process,
		_In_ PWCHAR DllPath,
		_In_ BOOLEAN IsWow64,
		_In_ PVOID LoadRoutine,
		_In_ PVOID SetEventRoutine,
		_Inout_ PNT_CREATESECTION_PAYLOAD CreateSectionCode,
		_Inout_ PNT_TESTALERT_PAYLOAD TestAlertCode,
		_In_ BOOLEAN IsInjectPPL)
	{
		auto pLdPyld = (PLOAD_PAYLOAD)
			DrvKit_Misc::AllocateUserMemory(
				ZwCurrentProcess(),
				sizeof(LOAD_PAYLOAD));

		UNICODE_STRING ntdllPath;
		UNICODE_STRING dllPath;

		if (pLdPyld == NULL) return NULL;

		BOOLEAN bNeedFree = FALSE;
		SIZE_T dllpathLen = wcslen(DllPath) * sizeof(WCHAR);


		if (dllpathLen > sizeof(pLdPyld->Data.Buffer))
		{
			DrvKit_ReportError("Loading dll size of path is too large.\n");
			bNeedFree = TRUE;
			goto cleanup;
		}

		RtlCopyMemory(pLdPyld->Data.Buffer, DllPath, dllpathLen);

		if (IsWow64)
		{
			RtlInitUnicodeString(&ntdllPath, WOW64_NTDLL_PATH);

			pLdPyld->Data.P.DllPath32.Length = dllpathLen;
			pLdPyld->Data.P.DllPath32.MaximumLength = dllpathLen + sizeof(WCHAR);
			pLdPyld->Data.P.DllPath32.Buffer = (ULONG)pLdPyld->Data.Buffer;
		}
		else
		{
			RtlInitUnicodeString(&ntdllPath, NATIVE_NTDLL_PATH);

			pLdPyld->Data.P.DllPath64.Length = dllpathLen;
			pLdPyld->Data.P.DllPath64.MaximumLength = dllpathLen + sizeof(WCHAR);
			pLdPyld->Data.P.DllPath64.Buffer = (ULONGLONG)pLdPyld->Data.Buffer;
		}

		if(TestAlertCode) TestAlertCode->Data.LoadShellCode = &pLdPyld->Code;
		
		pLdPyld->Data.Event = DrvKit_Misc::CreateEventForCurrentProcess();

		if (IsInjectPPL)
		{
			pLdPyld->Data.NtCreateSectionThread = (PVOID)&CreateSectionCode->Data.Tid;
		}
		else
		{
			pLdPyld->Data.NtCreateSectionThread = (PVOID)&pLdPyld->Data.NtCreateSectionThread;
		}

		pLdPyld->Data.LdrLoadDllRoutine = LoadRoutine;
		pLdPyld->Data.SetEventRoutine = SetEventRoutine;

		GenLoadShellcode(IsWow64, pLdPyld);

	cleanup:
		if (bNeedFree)
		{
			if (pLdPyld)
			{
				DrvKit_Misc::ReleaseUserMemory(ZwCurrentProcess(), pLdPyld, sizeof(LOAD_PAYLOAD));
				pLdPyld = NULL;
			}
		}

		return pLdPyld;
	}
	
	VOID DrvKit_Loader::LdrThreadWorker(_In_ PVOID Parameter)
	{
		PLDR_WORKER_ITEM pLdrWorkerItem = (PLDR_WORKER_ITEM)Parameter;

		PEPROCESS pProcess = NULL;
		NTSTATUS ntStatus;
		KAPC_STATE kApcState;
		HANDLE processId = (HANDLE)pLdrWorkerItem->ProcessId;
		PWCHAR pwszDllPath = pLdrWorkerItem->DllPath;

		ntStatus = PsLookupProcessByProcessId(processId, &pProcess);
		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("The Process(%d) doesn't exist.\n", processId);
			goto cleanup;
		}

		// 关闭ACG
		PROCESS_MITIGATION_DYNAMIC_CODE_POLICY newACG = { 0 };
		PROCESS_MITIGATION_DYNAMIC_CODE_POLICY oldACG = { 0 };

		if (DrvKit_Misc::m_OsBuildNumber >= 9200) // Win8.1
		{
			DrvKit_Mitigation::SetProcessMitigationPolicy(
				processId,
				ProcessDynamicCodePolicy,
				&newACG,
				&oldACG);
		}

		ntStatus = DrvKit_Misc::LockAndAttachProcess(pProcess, &kApcState);
		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("Can't attach target process: %d.\n", processId);
			goto cleanup;
		}

		if(pLdrWorkerItem->Unload) UnloadDllInternal(pProcess, pLdrWorkerItem->LoadBaseAddress, pLdrWorkerItem->Force);
		else ntStatus = LoadDllInternal(pProcess, pwszDllPath, &pLdrWorkerItem->LoadBaseAddress, pLdrWorkerItem->NtdllBase);

		DrvKit_Misc::UnLockAndDetachProcess(pProcess, &kApcState);

		if (DrvKit_Misc::m_OsBuildNumber >= 9200) // Win8.1
		{
			DrvKit_Mitigation::SetProcessMitigationPolicy(
				processId,
				ProcessDynamicCodePolicy,
				&oldACG);
		}

		pLdrWorkerItem->LdrStatus = ntStatus;

	cleanup:
		if (pProcess) ObDereferenceObject(pProcess);

		KeSetEvent(&pLdrWorkerItem->WaitEvent, IO_NO_INCREMENT, FALSE);
	}

	VOID DrvKit_Loader::GarbageCollect()
	{
		NTSTATUS ntStatus;
		PEPROCESS pProcess = NULL;
		KAPC_STATE kApcState;

		ExAcquireResourceExclusiveLite(&m_DustbinRWLock, TRUE);
		for (auto it = m_Dustbin->begin(); it != m_Dustbin->end();)
		{
			ntStatus = PsLookupProcessByProcessId((*it)->ProcessId, &pProcess);
			if (NT_SUCCESS(ntStatus))
			{
				ntStatus = DrvKit_Misc::LockAndAttachProcess(pProcess, &kApcState);
				if (NT_SUCCESS(ntStatus))
				{
					if ((*it)->LdrPayload->Data.Complete)
					{

						if ((*it)->HookCreSecInst)
						{
							ntStatus = (*it)->HookCreSecInst->UnHook();
							if (!NT_SUCCESS(ntStatus))
							{
								DrvKit_ReportError("Failed to unhook NtCreateSection. Code = %I32X\n", ntStatus);
							}
							delete (*it)->HookCreSecInst;
							(*it)->HookCreSecInst = NULL;
						}

						if ((*it)->HookTesAltInst)
						{
							ntStatus = (*it)->HookTesAltInst->UnHook();
							if (!NT_SUCCESS(ntStatus))
							{
								DrvKit_ReportError("Failed to unhook NtTestAlert. Code = %I32X\n", ntStatus);
							}
							delete (*it)->HookTesAltInst;
							(*it)->HookTesAltInst = NULL;
						}

						DrvKit_Misc::ReleaseUserMemory(ZwCurrentProcess(), (*it)->LdrPayload, sizeof(LOAD_PAYLOAD));
						delete (*it);
						*it = NULL;
						it = m_Dustbin->erase(it);
					}
					else
					{
						it++;
					}
					DrvKit_Misc::UnLockAndDetachProcess(pProcess, &kApcState);
				}
				else
				{
					it++;
				}
				ObDereferenceObject(pProcess);
			}
			else
			{
				if ((*it)->HookCreSecInst)
				{
					delete (*it)->HookCreSecInst;
					(*it)->HookCreSecInst = NULL;
				}

				if ((*it)->HookTesAltInst)
				{
					delete (*it)->HookTesAltInst;
					(*it)->HookTesAltInst = NULL;
				}

				delete (*it);
				*it = NULL;
				it = m_Dustbin->erase(it);
			}
		}

		ExReleaseResourceLite(&m_DustbinRWLock);
	}

	VOID DrvKit_Loader::ProcessCreateNotify(
		_In_ HANDLE ParentId,
		_In_ HANDLE ProcessId,
		_In_ BOOLEAN Create,
		_In_opt_ PBOOLEAN Next)
	{
		// ....
	}

	PVOID DrvKit_Loader::GetLoadedBaseAddress(HANDLE ProcessId, PWCHAR DllPath)
	{
		PEPROCESS pProcess;
		PVOID pLoadBase = NULL;
		KAPC_STATE kApcState;
		NTSTATUS ntStatus = PsLookupProcessByProcessId(ProcessId, &pProcess);
		if (NT_SUCCESS(ntStatus))
		{
			/*UNICODE_STRING uzDllPath;
			DrvKit_BinaryAnalyze bin(KernelMode);

			RtlInitUnicodeString(&uzDllPath, DllPath);
			if (bin.LoadFromFile(uzDllPath))
			{
				pLoadBase = DrvKit_Misc::GetUserModuleBaseByProcess(pProcess, !bin.IsX64(), DllPath);
			}*/

			ntStatus = DrvKit_Misc::LockAndAttachProcess(pProcess, &kApcState);
			if (NT_SUCCESS(ntStatus))
			{
				UNICODE_STRING uzDllPath;
				DrvKit_BinaryAnalyze bin(KernelMode);

				RtlInitUnicodeString(&uzDllPath, DllPath);
				DrvKit_FileMgmt file(uzDllPath);
				
				if (NT_SUCCESS(file.Open(OPEN_EXIST, GENERIC_READ)))
				{
					pLoadBase = file.GetMappedBaseAddress();
					if (!bin.LoadFromMap((PUCHAR)pLoadBase))
					{
						pLoadBase = NULL;
					}
				}
				DrvKit_Misc::UnLockAndDetachProcess(pProcess, &kApcState);
			}
			ObDereferenceObject(pProcess);
		}
		return pLoadBase;
	}

	NTSTATUS DrvKit_Loader::LoadDllInternal(
		_In_ PEPROCESS Process,
		_In_ PWCHAR DllPath,
		_Inout_ PVOID* LoadBaseAddress,
		_In_opt_ PVOID NtdllBase)
	{
		BOOLEAN bIsPPL = PsIsProtectedProcess(Process);
#ifdef _AMD64_
		BOOLEAN bIsWow64 = PsGetProcessWow64Process(Process) != NULL;
#else
		BOOLEAN bIsWow64 = TRUE;
#endif _AMD64_
		NTSTATUS bRet = STATUS_UNSUCCESSFUL;
		UNICODE_STRING ntdllPath;
		PNT_CREATESECTION_PAYLOAD pCreateSectionCode = NULL;
		PNT_TESTALERT_PAYLOAD pTestAlertCode = NULL;
		SIZE_T cbSection, cbAlert;
		PLOAD_PAYLOAD pLdPyld = NULL;
		PVOID pfnNtCreateSection = NULL;
		PVOID pfnNtTestAlert = NULL;
		PVOID pfnLoadDllRoutine = NULL;
		PVOID pfnSetEventRoutine = NULL;
		PVOID pfnTestFunc = NULL;
		DrvKit_BinaryAnalyze bin(UserMode);
		UNICODE_STRING dllPath;
		DrvKit_HookEng* hookSection = NULL;
		DrvKit_HookEng* hookAlert = NULL;
		HANDLE hSection = NULL;
		PKEVENT pEvent = NULL;
		NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
		HANDLE hThread = NULL;
		PETHREAD pThread = NULL;
		LARGE_INTEGER timeout = { 0 };

		// 释放资源
		GarbageCollect();

		if (NtdllBase == NULL)
		{

			// 不管是Native进程还是Wow64进程，Ldr中ntdll的路径都是C:\windows\system32\ntdll.dll
			NtdllBase = (PUCHAR)DrvKit_Misc::GetUserModuleBaseByProcess(
				Process,
				bIsWow64,
				NATIVE_NTDLL_PATH);

			if (NtdllBase == NULL) goto cleanup;
		}

		if (!bin.LoadFromMap((PUCHAR)NtdllBase))
		{
			goto cleanup;
		}

		hookAlert = new DrvKit_HookEng(bin.GetImageLoadBase(), bin.GetImageSize());
		if (hookAlert == NULL) goto cleanup;

		hookAlert->SetBitWidth(!bin.IsX64());
		
		pfnLoadDllRoutine = bin.GetFunAddressFromEAT("LdrLoadDll");

		if (pfnLoadDllRoutine == NULL)
		{
			DrvKit_ReportError("Can't find LdrLoadDll.\n");
			goto cleanup;
		}

		pfnSetEventRoutine = bin.GetFunAddressFromEAT("NtSetEvent");

		if (pfnSetEventRoutine == NULL)
		{
			DrvKit_ReportError("Can't find NtSetEvent.\n");
			goto cleanup;
		}

		pfnNtTestAlert = bin.GetFunAddressFromEAT("NtTestAlert");

		if (pfnNtTestAlert == NULL)
		{
			DrvKit_ReportError("Can't find NtTestAlert.\n");
			goto cleanup;
		}

		pTestAlertCode = hookAlert->GenNtTestAlertCode(
			pfnNtTestAlert,
			&cbAlert);

		if (pTestAlertCode == NULL)
		{
			DrvKit_ReportError("Cant't make code for NtTestAlert.\n");
			goto cleanup;
		}

		if (bIsPPL)
		{
			hookSection = new DrvKit_HookEng(bin.GetImageLoadBase(), bin.GetImageSize());
			if (hookAlert == NULL) goto cleanup;

			hookSection->SetBitWidth(!bin.IsX64());
			pfnNtCreateSection = bin.GetFunAddressFromEAT("NtCreateSection");

			pCreateSectionCode = hookSection->GenNtCreateSectionCode(
				pfnNtCreateSection,
				&cbSection);

			if (pCreateSectionCode == NULL)
			{
				DrvKit_ReportError("Cant't make code for NtCreateSection.\n");
				goto cleanup;
			}

			RtlInitUnicodeString(&dllPath, DllPath);
			hSection = DrvKit_Misc::CreateSectionByFile(dllPath);
			if (hSection == NULL)
			{
				DrvKit_ReportError("Cant't make code for NtCreateSection.\n");
				goto cleanup;
			}
		}

		// 对NtTestAlert和NtCreateSection两个函数的patch code进行初始化
		if (pCreateSectionCode)
		{
			pCreateSectionCode->Data.SectionHandle = hSection;
		}

		pLdPyld = PrepareLoadPayload(
			Process,
			DllPath,
			!bin.IsX64(),
			pfnLoadDllRoutine,
			pfnSetEventRoutine,
			pCreateSectionCode,
			pTestAlertCode,
			bIsPPL);

		if (pLdPyld == NULL)
		{
			goto cleanup;
		}

		ntStatus = ObReferenceObjectByHandle(
			pLdPyld->Data.Event, 
			EVENT_MODIFY_STATE, 
			*ExEventObjectType, 
			UserMode, 
			(PVOID*)&pEvent, 
			NULL);

		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("Can't get event object.\n");
			goto cleanup;
		}

		if (pfnNtCreateSection)
		{
			ntStatus = hookSection->Hook(pfnNtCreateSection, &pCreateSectionCode->Code, NULL);
			if (!NT_SUCCESS(ntStatus))
			{
				DrvKit_ReportError("Can't hook NtCreateSection -- Error: %I32x\n", ntStatus);
				goto cleanup;
			}
		}

		ntStatus = hookAlert->Hook(pfnNtTestAlert, &pTestAlertCode->Code, NULL);
		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("Can't hook NtTestAlert -- Error: %I32x\n", ntStatus);
			goto cleanup;
		}

		KeResetEvent(pEvent);

		pfnTestFunc = bin.GetFunAddressFromEAT("RtlUpperChar");
		if (pfnTestFunc == NULL)
		{
			ntStatus = STATUS_NOT_FOUND;
			goto cleanup;
		}

		hThread = DrvKit_Misc::CreateUserThread(
			ZwCurrentProcess(),
			pfnTestFunc,
			pLdPyld->Data.Buffer,
			FALSE);

		if (hThread == NULL)
		{
			DrvKit_ReportError("Failed to create thread.\n");
			goto cleanup;
		}

		timeout.QuadPart = -(10ll * 10 * 1000 * 1000);  // 等待完成事件10s
		ntStatus = KeWaitForSingleObject(pEvent, Executive, UserMode, TRUE, &timeout);

		timeout.QuadPart = -(30ll * 10 * 1000 * 1000);  // 等待线程结束30s
		ntStatus = ZwWaitForSingleObject(hThread, TRUE, &timeout);

		if (pLdPyld->Data.Complete)
		{
			bRet = pLdPyld->Data.Status;

			if (NT_SUCCESS(pLdPyld->Data.Status))
			{
				if (LoadBaseAddress) *LoadBaseAddress = pLdPyld->Data.LoadBaseAddress;
			}
		}

	cleanup:
		if (hThread) ZwClose(hThread);

		if (ntStatus != STATUS_TIMEOUT)
		{
			if (hookAlert)
			{
				hookAlert->UnHook();
				delete hookAlert;
			}

			if (hookSection)
			{
				hookSection->UnHook();
				delete hookSection;
			}
			
			if (pLdPyld)
			{
				DrvKit_Misc::ReleaseUserMemory(ZwCurrentProcess(), pLdPyld, sizeof(LOAD_PAYLOAD));
			}
		}
		else
		{
			PGARBAGE_ITEM pGarbageItem = new GARBAGE_ITEM;
			if (pGarbageItem == NULL)
			{
				// 极限情况，只能保证内核内存不泄露，不能保证被注入的R3内存不泄露
				if (hookAlert) delete hookAlert;
				if (hookSection) delete hookSection;
			}
			else
			{
				// 丢到垃圾箱，延迟释放

				pGarbageItem->ProcessId = PsGetProcessId(Process);
				pGarbageItem->HookCreSecInst = hookSection;
				pGarbageItem->HookTesAltInst = hookAlert;
				pGarbageItem->LdrPayload = pLdPyld;

				ExAcquireResourceExclusiveLite(&m_DustbinRWLock, TRUE);
				m_Dustbin->push_back(pGarbageItem);
				ExReleaseResourceLite(&m_DustbinRWLock);
			}
		}
		
		
		if (pEvent) ObDereferenceObject(pEvent);

		return bRet;
	}

	VOID DrvKit_Loader::UnloadDllInternal(
		_In_ PEPROCESS Process,
		_Inout_ PVOID LoadBaseAddress,
		_In_ BOOLEAN ForceUnload)
	{
#ifdef _AMD64_
		BOOLEAN bIsWow64 = PsGetProcessWow64Process(Process) != NULL;
#else
		BOOLEAN bIsWow64 = TRUE;
#endif _AMD64_

		DrvKit_BinaryAnalyze bin(UserMode);

		if (bin.LoadFromMap(
			(PUCHAR)DrvKit_Misc::GetUserModuleBaseByProcess(
				Process,
				bIsWow64,
				NATIVE_NTDLL_PATH)))
		{
			PVOID pfn = bin.GetFunAddressFromEAT("LdrUnloadDll");
			if (pfn == NULL) goto exit;

			if (ForceUnload) 
				ZwUnmapViewOfSection(ZwCurrentProcess(), LoadBaseAddress);
			else 
				DrvKit_UserCall::UserModeCall(pfn, 1, LoadBaseAddress);
		}
	exit:
		return;
	}

	NTSTATUS DrvKit_Loader::LoadDll(
		_In_ ULONG ProcessId, 
		_In_ PWCHAR DllPath, 
		_Inout_ PVOID* LoadBaseAddress,
		_In_opt_ PVOID NtdllBase)
	{
		LDR_WORKER_ITEM LdrWorkerItem = { 0 };
		
		if (m_Inited == FALSE || m_Shutdown == TRUE) return STATUS_UNSUCCESSFUL;

		{
			UNICODE_STRING dllPath;
			DrvKit_BinaryAnalyze dll(KernelMode);
			RtlInitUnicodeString(&dllPath, DllPath);

			if (!dll.LoadFromFile(dllPath))
			{
				goto end;
			}

#ifdef _AMD64_
			if (!dll.IsX64() && DrvKit_Misc::IsWow64Process((HANDLE)ProcessId))
			{
				// 在64位系统下64位dll可以注入到32位进程，但32位dll不能注入到64位进程。
				DrvKit_ReportError("Can't inject 32bit DLL into 64bit process.\n");
				goto end;
			}

#endif _AMD64_
		}

		KeInitializeEvent(&LdrWorkerItem.WaitEvent, SynchronizationEvent, FALSE);

		LdrWorkerItem.ProcessId = ProcessId;
		LdrWorkerItem.DllPath = DllPath;
		LdrWorkerItem.NtdllBase = NtdllBase;
		LdrWorkerItem.Unload = FALSE;

		ExInitializeWorkItem(
			&LdrWorkerItem.LdrQueuWorker,
			DrvKit_Loader::LdrThreadWorker,
			&LdrWorkerItem);
		
		// 以实时优先级执行线程
		ExQueueWorkItem(&LdrWorkerItem.LdrQueuWorker, CriticalWorkQueue);

		KeWaitForSingleObject(&LdrWorkerItem.WaitEvent, Executive, KernelMode, FALSE, NULL);
		*LoadBaseAddress = LdrWorkerItem.LoadBaseAddress;

	end:
		return LdrWorkerItem.LdrStatus;
	}

	VOID DrvKit_Loader::UnLoadDll(
		_In_ ULONG ProcessId,
		_Inout_ PVOID LoadBaseAddress,
		_In_ BOOLEAN ForceUnload)
	{
		PEPROCESS pProcess = NULL;
		NTSTATUS ntStatus;
		KAPC_STATE kApcState;

		if (m_Inited == FALSE || m_Shutdown == TRUE) return;

		LDR_WORKER_ITEM LdrWorkerItem = { 0 };

		KeInitializeEvent(&LdrWorkerItem.WaitEvent, SynchronizationEvent, FALSE);

		LdrWorkerItem.ProcessId = ProcessId;
		LdrWorkerItem.LoadBaseAddress = LoadBaseAddress;
		LdrWorkerItem.Force = ForceUnload;
		LdrWorkerItem.Unload = TRUE;

		ExInitializeWorkItem(
			&LdrWorkerItem.LdrQueuWorker,
			DrvKit_Loader::LdrThreadWorker,
			&LdrWorkerItem);

		// 以实时优先级执行线程
		ExQueueWorkItem(&LdrWorkerItem.LdrQueuWorker, CriticalWorkQueue);

		KeWaitForSingleObject(&LdrWorkerItem.WaitEvent, Executive, KernelMode, FALSE, NULL);


	//	ntStatus = PsLookupProcessByProcessId((HANDLE)ProcessId, &pProcess);
	//	if (!NT_SUCCESS(ntStatus))
	//	{
	//		DrvKit_ReportError("The Process(%d) doesn't exist.\n", ProcessId);
	//		goto cleanup;
	//	}
	//	
	//	// 关闭ACG
	//	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY newACG = { 0 };
	//	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY oldACG = { 0 };

	//	if (DrvKit_Misc::m_OsBuildNumber >= 9200) // Win8.1
	//	{
	//		DrvKit_Mitigation::SetProcessMitigationPolicy(
	//			(HANDLE)ProcessId,
	//			ProcessDynamicCodePolicy,
	//			&newACG,
	//			&oldACG);
	//	}

	//	ntStatus = DrvKit_Misc::LockAndAttachProcess(pProcess, &kApcState);
	//	if (NT_SUCCESS(ntStatus))
	//	{
	//		
	//		UnloadDllInternal(pProcess, LoadBaseAddress, ForceUnload);

	//		DrvKit_Misc::UnLockAndDetachProcess(pProcess, &kApcState);
	//	}

	//	if (DrvKit_Misc::m_OsBuildNumber >= 9200) // Win8.1
	//	{
	//		DrvKit_Mitigation::SetProcessMitigationPolicy(
	//			(HANDLE)ProcessId,
	//			ProcessDynamicCodePolicy,
	//			&oldACG,
	//			NULL);
	//	}

	//cleanup:

	//	if (pProcess) ObDereferenceObject(pProcess);
	}

	VOID DrvKit_Loader::ReleaseDustbin()
	{
		for (auto it = m_Dustbin->begin(); it != m_Dustbin->end();)
		{
			if ((*it)->HookCreSecInst) delete (*it)->HookCreSecInst;

			if ((*it)->HookTesAltInst) delete (*it)->HookTesAltInst;

			delete (*it);
			it = m_Dustbin->erase(it);
		}

		delete m_Dustbin;
		m_Dustbin = NULL;
	}
};