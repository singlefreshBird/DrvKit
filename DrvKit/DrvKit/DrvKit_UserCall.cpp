#include "DrvKit_UserCall.h"
#include "DrvKit_BinaryAnalyze.h"
#include "DrvKit_FileMgmt.h"
#include "DrvKit_Private.h"
#include "DrvKit_Misc.h"
#include <stdarg.h>

namespace DK
{
	DrvKit_UserCall::DrvKit_UserCall()
	{

	}

	DrvKit_UserCall::~DrvKit_UserCall()
	{

	}

	BOOLEAN DrvKit_UserCall::DoCallUser(_In_ PVOID Payload)
	{
		BOOLEAN bRet = FALSE;
		HANDLE hThread = NULL;
		NTSTATUS ntStatus;
		OBJECT_ATTRIBUTES oa;
		ULONG ulSuspendCount;
		LARGE_INTEGER timeout = { 0 };
		timeout.QuadPart = -(30ll * 10 * 1000 * 1000); // 30s

		InitializeObjectAttributes(&oa, NULL, NULL, NULL, NULL);

		ntStatus = DrvKit_Private::m_pfnZwCreateThreadEx(
			&hThread,
			THREAD_QUERY_LIMITED_INFORMATION,
			&oa,
			ZwCurrentProcess(),
			Payload,
			NULL,
			0, //THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
			0,
			0x1000,
			0x100000,
			NULL);
		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("Can't spawn new thread. Code = %I32X\n",ntStatus);
			goto cleanup;
		}

		ZwWaitForSingleObject(hThread, TRUE, &timeout);

		bRet = TRUE;

	cleanup:
		if (hThread)
		{
			ZwClose(hThread);
		}

		return bRet;
	}
	
	VOID DrvKit_UserCall::PackParam(
		_In_ BOOLEAN Wow64,
		_Inout_ PCALL_PAYLOAD CallPayload,
		_In_ PVOID Func,
		_In_ ULONG Argc,
		_In_ va_list param)
	{
		ULONG ulOff;
		UCHAR ucDiff = 0x28;

		CallPayload->Data.FunctionAddress = Func;   
		
		if (Wow64)
		{
			/*
			 * push ebp
			 * mov ebp,esp
			 * sub esp,100
			 */
			RtlCopyMemory(
				CallPayload->Code.Shellcode32.Prologue,
				"\x55\x8B\xEC\x81\xEC\x00\x01\x00\x00",
				9);

			for (LONG i = Argc - 1; i >= 0; i--)
			{
				// push xxx
				CallPayload->Code.Shellcode32.StackPassArg[i][0] = 0x68;
				*(PULONG)(CallPayload->Code.Shellcode32.StackPassArg[i] + 1) = (ULONG)va_arg(param, PVOID);
			}
			
			PCALL_SHELLCODE32 pSc = (PCALL_SHELLCODE32)
				((PUCHAR)&CallPayload->Code.Shellcode32 -
					//FIELD_OFFSET(CALL_SHELLCODE32, Call) -
					(MAX_NUM_OF_PARAM - Argc) * 
					sizeof(CallPayload->Code.Shellcode32.StackPassArg[0]));

			// call dword ptr ds:[FunctionAddress]
			pSc->Call[0] = 0xFF;
			pSc->Call[1] = 0x15;
			*(PULONG)(pSc->Call + 2) = (ULONG)&CallPayload->Data.FunctionAddress;

			// mov dword ptr ds:[&RetValue],eax
			pSc->SaveRetValueCode[0] = 0xA3;
			*(PULONG)(pSc->SaveRetValueCode + 1) = (ULONG)&CallPayload->Data.RetValue;
			
			// mov byte ptr ds:[&Completed],1
			pSc->CompleteCode[0] = 0xC6;
			pSc->CompleteCode[1] = 0x05;
			*(PULONG)(pSc->CompleteCode + 2) = (ULONG)&CallPayload->Data.Completed;
			pSc->CompleteCode[6] = TRUE;

			/*
			 * add esp,100
			 * leave
			 * ret
			 */

			RtlCopyMemory(
				pSc->Epilogue,
				"\x81\xC4\x00\x01\x00\x00\xC9\xC3",
				8);
		}
		else
		{
			RtlCopyMemory(
				CallPayload->Code.Shellcode64.Prologue,
				"\x48\x89\x4c\x24\x08\x48\x89\x54\x24"
				"\x10\x4c\x89\x44\x24\x18\x4c\x89\x4c"
				"\x24\x20\x48\x83\xec\x28",
				24);

			if (Argc > 4)
			{
				ucDiff = Argc * sizeof(PVOID);

				if (ucDiff % 0x10) ucDiff = ((ucDiff / 0x10) + 1) * 0x10 + sizeof(PVOID);

				CallPayload->Code.Shellcode64.Prologue[23] = ucDiff;

				ulOff = sizeof(CallPayload->Code.Shellcode64.RegPassArgv) +
					(Argc - 4) * sizeof(CallPayload->Code.Shellcode64.StackPassArg[0]);
			}
			else
			{
				ulOff = Argc * sizeof(CallPayload->Code.Shellcode64.RegPassArgv[0]);
			}

			for (ULONG i = 0; i < Argc; i++)
			{
				if (i == 0)
				{
					// movabs rcx,imm
					CallPayload->Code.Shellcode64.RegPassArgv[i][0] = 0x48;
					CallPayload->Code.Shellcode64.RegPassArgv[i][1] = 0xB9;
					*(PULONG64)(CallPayload->Code.Shellcode64.RegPassArgv[i] + 2) = (ULONG64)va_arg(param, PVOID);
				}
				else if (i == 1)
				{
					// movabs rdx,imm
					CallPayload->Code.Shellcode64.RegPassArgv[i][0] = 0x48;
					CallPayload->Code.Shellcode64.RegPassArgv[i][1] = 0xBA;
					*(PULONG64)(CallPayload->Code.Shellcode64.RegPassArgv[i] + 2) = (ULONG64)va_arg(param, PVOID);
				}
				else if (i == 2)
				{
					// movabs r8,imm
					CallPayload->Code.Shellcode64.RegPassArgv[i][0] = 0x49;
					CallPayload->Code.Shellcode64.RegPassArgv[i][1] = 0xB8;
					*(PULONG64)(CallPayload->Code.Shellcode64.RegPassArgv[i] + 2) = (ULONG64)va_arg(param, PVOID);
				}
				else if (i == 3)
				{
					// movabs r9,imm
					CallPayload->Code.Shellcode64.RegPassArgv[i][0] = 0x49;
					CallPayload->Code.Shellcode64.RegPassArgv[i][1] = 0xB9;
					*(PULONG64)(CallPayload->Code.Shellcode64.RegPassArgv[i] + 2) = (ULONG64)va_arg(param, PVOID);
				}
				else
				{
					CallPayload->Code.Shellcode64.StackPassArg[i - 4][0] = 0x48;
					CallPayload->Code.Shellcode64.StackPassArg[i - 4][1] = 0xB8;
					*(PULONG64)(CallPayload->Code.Shellcode64.StackPassArg[i - 4] + 2) = (ULONG64)va_arg(param, PVOID);
					CallPayload->Code.Shellcode64.StackPassArg[i - 4][10] = 0x48;
					CallPayload->Code.Shellcode64.StackPassArg[i - 4][11] = 0x89;
					CallPayload->Code.Shellcode64.StackPassArg[i - 4][12] = 0x84;
					CallPayload->Code.Shellcode64.StackPassArg[i - 4][13] = 0x24;
					*(PULONG)(CallPayload->Code.Shellcode64.StackPassArg[i - 4] + 14) = 0x20 + (Argc - i - 1) * sizeof(PVOID);
				}
			}
			
			
			PCALL_SHELLCODE64 pSc = (PCALL_SHELLCODE64)
				((PUCHAR)&CallPayload->Code.Shellcode64 - 
				(sizeof(CallPayload->Code.Shellcode64.RegPassArgv) +
				sizeof(CallPayload->Code.Shellcode64.StackPassArg) - 
				ulOff));

			// call qword ptr ds:[rip+xxx]
			pSc->Call[0] = 0xFF;
			pSc->Call[1] = 0x15;
			*(PLONG)(pSc->Call + 2) =
				(LONG64)&CallPayload->Data.FunctionAddress -
				(LONG64)pSc->Call - 
				sizeof(pSc->Call);

			pSc->SaveRetValueCode[0] = 0x48;
			pSc->SaveRetValueCode[1] = 0x89;
			pSc->SaveRetValueCode[2] = 0x05;
			*(PLONG)(pSc->SaveRetValueCode + 3) =
				(LONG64)&CallPayload->Data.RetValue -
				(LONG64)pSc->SaveRetValueCode -
				sizeof(pSc->SaveRetValueCode);

			pSc->CompleteCode[0] = 0xC6;
			pSc->CompleteCode[1] = 0x05;
			*(PLONG)(pSc->CompleteCode + 2) = 
				(LONG64)&CallPayload->Data.Completed -
				(LONG64)pSc->CompleteCode - 
				sizeof(pSc->CompleteCode);
			pSc->CompleteCode[6] = TRUE;

			RtlCopyMemory(
				pSc->Epilogue,
				"\x48\x83\xc4\x28\x48\x8b\x4c\x24"
				"\x08\x48\x8b\x54\x24\x10\x4c\x8b"
				"\x44\x24\x18\x4c\x8b\x4c\x24\x20\xC3",
				25);

			pSc->Epilogue[3] = ucDiff;
		}
	}

	PVOID DrvKit_UserCall::UserModeCall(
		_In_ PVOID Func,
		_In_ ULONG Argc,
		_In_ PVOID Argv,
		...)
	{
		va_list val;
		va_start(val, Argc);

		PVOID pResult = NULL;
#ifdef _AMD64_
		BOOLEAN bIsWow64 = PsGetCurrentProcessWow64Process() != NULL;
#else
		BOOLEAN bIsWow64 = TRUE;
#endif

		PCALL_PAYLOAD pCallPyld = (PCALL_PAYLOAD)
			DrvKit_Misc::AllocateUserMemory(
				ZwCurrentProcess(), 
				sizeof(CALL_PAYLOAD));

		if (pCallPyld == NULL) goto cleanup;

		PackParam(bIsWow64, pCallPyld, Func, Argc, val);

		if (DoCallUser(&pCallPyld->Code))
		{
			if(pCallPyld->Data.Completed) pResult = pCallPyld->Data.RetValue;
		}

	cleanup:
		if (pCallPyld)
		{
			DrvKit_Misc::ReleaseUserMemory(
				ZwCurrentProcess(),
				pCallPyld,
				sizeof(CALL_PAYLOAD));
		}
		va_end(val);

		return pResult;
	}
};

