#include "DrvKit_HookEng.h"
#include "DrvKit_Misc.h"
#include "DrvKit_Private.h"
#include <BeaEngine.h>

#pragma comment(lib,"BeaEngine.lib")

namespace DK
{
	DrvKit_HookEng::DrvKit_HookEng(PVOID BaseLoadAddress, SIZE_T ImageSize):
		m_BaseLoadAddress(BaseLoadAddress),
		m_ImageSize(ImageSize),
		m_prvSaveByteCode{0},
		m_prvPatchAddress(NULL),
		m_prvTrampoline(NULL),
		m_prvTrampolineSize(0),
		m_prvIsWow64(FALSE)
	{}

	DrvKit_HookEng::DrvKit_HookEng(PVOID BaseLoadAddress, SIZE_T ImageSize, BOOLEAN IsWow64):
		m_BaseLoadAddress(BaseLoadAddress),
		m_ImageSize(ImageSize),
		m_prvSaveByteCode{ 0 },
		m_prvPatchAddress(NULL),
		m_prvTrampoline(NULL),
		m_prvTrampolineSize(0),
		m_prvIsWow64(IsWow64)
	{}

	DrvKit_HookEng::~DrvKit_HookEng(){}

	VOID DrvKit_HookEng::FixRelativeAddress(PVOID Address, PVOID NewBaseAddress, ULONG Size)
	{
#ifdef _AMD64_
		// 只需处理x64相对Rip偏移寻址的情况，这种情况下只会存在两个操作数
		if (m_prvIsWow64) return;
		
		DISASM disAsm = { 0 };
		disAsm.EIP = (UIntPtr)Address;
		disAsm.VirtualAddr = (UIntPtr)Address;
		PUCHAR pEnd = (PUCHAR)(disAsm.EIP + Size);
		LONG len;

		while (disAsm.Error >= 0)
		{
			disAsm.SecurityBlock = (UIntPtr)pEnd - disAsm.EIP;
			if ((Int32)disAsm.SecurityBlock <= 0) break;

			len = Disasm(&disAsm);

			switch (disAsm.Error)
			{
			case OUT_OF_BLOCK:
				break;
			case UNKNOWN_OPCODE:
				disAsm.EIP += 1;
				disAsm.VirtualAddr += 1;
				break;
			default:
			{
				// 常见的应该就是以下这些了，古怪刁专的那种奇葩老子不处理了。

				if (disAsm.Operand1.OpSize && disAsm.Operand2.OpSize)
				{
					int diff = disAsm.VirtualAddr - (UIntPtr)NewBaseAddress;
					int off;

					switch (*(int*)disAsm.Instruction.Mnemonic)
					{
					case 'vom':
					case 'ael':
					case 'bus':
					case 'dda':
					case 'rox':
					case 'cni':
					case 'ced':
					case 'pmc':
					case 'tset':
					{
						if (disAsm.Operand1.OpType == 0x4030000)
						{
							off = disAsm.EIP - (ULONG_PTR)Address;
							*(PLONG)((ULONG_PTR)NewBaseAddress + off + 3) = disAsm.Operand1.Memory.Displacement + diff;
						}
						else if (disAsm.Operand2.OpType == 0x4030000)
						{
							off = disAsm.EIP - (ULONG_PTR)Address;
							*(PLONG)((ULONG_PTR)NewBaseAddress + off + 3) = disAsm.Operand2.Memory.Displacement + diff;
						}
						break;
					}
					case 'hsup':
					case 'pop':
					case 'llac':
					{
						if (disAsm.Operand1.OpType == 0x4030000)
						{
							off = disAsm.EIP - (ULONG_PTR)Address;
							*(PLONG)((ULONG_PTR)NewBaseAddress + off + 2) = disAsm.Operand1.Memory.Displacement + diff;
						}
						else if (disAsm.Operand2.OpType == 0x4030000)
						{
							off = disAsm.EIP - (ULONG_PTR)Address;
							*(PLONG)((ULONG_PTR)NewBaseAddress + off + 2) = disAsm.Operand2.Memory.Displacement + diff;
						}
						break;
					}
					default:
						break;
					}

				}
				
				disAsm.EIP += len;
				disAsm.VirtualAddr += len;
				break;
			}
			}
		}

#endif
	}

	PVOID DrvKit_HookEng::AllocTrampoline(PVOID TargetFunc, PVOID ProxyFunc, ULONG Size)
	{
		UCHAR trampoline64[14] = { 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
		UCHAR trampoline32[5] = { 0xE9,0,0,0,0 };
		PVOID pTargetAddress = NULL;

		if (m_prvIsWow64)
		{
			pTargetAddress = DrvKit_Misc::AllocateUserMemory(
				NtCurrentProcess(),
				Size +
				sizeof(trampoline32));

			RtlCopyMemory(
				pTargetAddress,
				TargetFunc,
				Size);
			*(PLONG)(trampoline32 + 1) =
				((LONG)TargetFunc +
					Size) -
				(LONG)pTargetAddress -
				sizeof(trampoline32);

			RtlCopyMemory(
				(PUCHAR)pTargetAddress +
				Size,
				trampoline32,
				sizeof(trampoline32));

			m_prvTrampoline = (PUCHAR)pTargetAddress;
			m_prvTrampolineSize =
				Size +
				sizeof(trampoline32);
		}
		else
		{
			pTargetAddress = DrvKit_Misc::AllocateUserMemory(
				NtCurrentProcess(),
				Size +
				sizeof(trampoline64));

			RtlCopyMemory(
				pTargetAddress,
				TargetFunc,
				Size);

			*(PULONG64)(trampoline64 + 6) =
				(ULONG64)TargetFunc +
				Size;

			RtlCopyMemory(
				(PUCHAR)pTargetAddress +
				Size,
				trampoline64,
				sizeof(trampoline64));

			m_prvTrampoline = (PUCHAR)pTargetAddress;
			m_prvTrampolineSize =
				Size +
				sizeof(trampoline64);

			FixRelativeAddress(TargetFunc, pTargetAddress, Size);
		}

		return pTargetAddress;
	}

	NTSTATUS DrvKit_HookEng::Hook(PVOID TargetFunc, PVOID ProxyFunc, PVOID* OldFunc)
	{
		UCHAR trampoline64[14] = { 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
		UCHAR trampoline32[5] = { 0xE9,0,0,0,0 };
		PVOID pActualPatchAddr;
		ULONG miniSize;
		NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
		PUCHAR pPatchAddress;
		ULONG ulOldProt;
		SIZE_T protSize = 0x20;
		SIZE_T writtenSize;

		__try
		{
			ProbeForRead(TargetFunc, 0x40, 1);

			pActualPatchAddr = SkipBranchIns(TargetFunc, &miniSize);
			if (pActualPatchAddr == NULL) goto end;

			ProbeForRead(pActualPatchAddr, 0x40, 1);

			m_prvPatchAddress = (PUCHAR)pActualPatchAddr;

			if (OldFunc)
			{
				if (m_prvIsWow64)
				{
					*OldFunc = AllocTrampoline(pActualPatchAddr, ProxyFunc, miniSize);
					*(PLONG)(trampoline32 + 1) =
						(ULONG)*OldFunc -
						(LONG)pActualPatchAddr -
						sizeof(trampoline32);
				}
				else
				{
					*OldFunc = AllocTrampoline(pActualPatchAddr, ProxyFunc, miniSize);
					*(PULONG64)(trampoline64 + 6) = *(PULONG64)OldFunc;
				}
			}

			pPatchAddress = (PUCHAR)pActualPatchAddr;

			// 保存一下原来的指令
			RtlCopyMemory(
				m_prvSaveByteCode, 
				pActualPatchAddr, 
				sizeof(m_prvSaveByteCode));
			
			ntStatus = DrvKit_Private::m_pfnZwProtectVirtualMemory(
				NtCurrentProcess(),
				(PVOID*)&pActualPatchAddr,
				&protSize,
				PAGE_EXECUTE_READWRITE,
				&ulOldProt);

			if (NT_SUCCESS(ntStatus))
			{
				if (m_prvIsWow64)
				{
					*(PLONG)(trampoline32 + 1) = 
						(LONG)ProxyFunc -
						(LONG)pPatchAddress -
						sizeof(trampoline32);

					ntStatus = DrvKit_Misc::WriteUserMemory(
						NtCurrentProcess(),
						pPatchAddress,
						trampoline32,
						sizeof(trampoline32));
							
					ntStatus = DrvKit_Private::m_pfnZwFlushInstructionCache(
						NtCurrentProcess(),
						pPatchAddress,
						sizeof(trampoline32));
				}
				else
				{
					*(PULONG64)(trampoline64 + 6) = (ULONG64)ProxyFunc;
					ntStatus = DrvKit_Misc::WriteUserMemory(
						NtCurrentProcess(),
						pPatchAddress,
						trampoline64,
						sizeof(trampoline64));

					ntStatus = DrvKit_Private::m_pfnZwFlushInstructionCache(
						NtCurrentProcess(),
						pPatchAddress,
						sizeof(trampoline64));
				}
						
				if (!NT_SUCCESS(ntStatus))
				{
					DrvKit_ReportError(
						"Can't patch address: %p -- Error code: %I32x\n", 
						pPatchAddress,
						ntStatus);

					goto end;
				}

				// 保护改不回去也无所谓
				DrvKit_Private::m_pfnZwProtectVirtualMemory(
					NtCurrentProcess(),
					(PVOID*)&pActualPatchAddr,
					&protSize,
					ulOldProt,
					&ulOldProt);

			}
			else
			{
				DrvKit_ReportError(
					"Failed to call ZwProtectVirtualMemory. Error code: %I32x\n",
					ntStatus);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DrvKit_ReportException("An exception occurred! Exception code = %I32X\n", GetExceptionCode());
		}

	end:
		return ntStatus;
	}

	PVOID DrvKit_HookEng::SkipBranchIns(PVOID Address, PULONG DecodeLen)
	{
		DISASM disAsm = { 0 };

		disAsm.EIP = (UIntPtr)Address;
		disAsm.VirtualAddr = (UIntPtr)Address;
		disAsm.Archi = m_prvIsWow64 ? 0x20 : 0x40;

		PCHAR pEnd = (PCHAR)disAsm.EIP + 0x40;
		ULONG len;
		ULONG sum = 0;
		ULONG limit = 0;

		__try
		{
			while (disAsm.Error >= 0 &&
				sum < (m_prvIsWow64 ? 5 : 14) &&
				limit < 0xFFF) // 0x40个字节范围内的指令没理由解码0xFFF次还不结束，唯一的解释就是指令存在死循环。
			{
				limit++;
				disAsm.SecurityBlock = (UIntPtr)pEnd - disAsm.EIP;
				if ((Int32)disAsm.SecurityBlock <= 0) break;

				len = Disasm(&disAsm);

				switch (disAsm.Error)
				{
				case OUT_OF_BLOCK:
					break;
				case UNKNOWN_OPCODE:
					disAsm.EIP += 1;
					disAsm.VirtualAddr += 1;
					sum += 1;
					break;
				default:
				{
					switch (disAsm.Instruction.BranchType)
					{
					case 0x3:			// je
					case 0x8:			// jg
					case 0xfffffffd:	// jne
					case 0xfffffff8:	// jle
					case 0xfffffff9:	// jnl
					{
						// 解析跳转的时候得小心循环，这里直接忽略向上的短跳
						if (disAsm.VirtualAddr < disAsm.Instruction.AddrValue)
						{
							disAsm.EIP = disAsm.Instruction.AddrValue;
							disAsm.VirtualAddr = disAsm.Instruction.AddrValue;
							sum = 0;
							continue;
						}
						else
						{
							break;
						}
					}
					case 0xb:			// jmp
					{
						if (disAsm.Operand1.OpType == 0x4030000)
						{
							// 如果跳转目标不在本模块内部，则说明被第三方patch了
							auto target = *(UIntPtr*)disAsm.Instruction.AddrValue;
							if ((ULONG_PTR)m_BaseLoadAddress <= target && target < (ULONG_PTR)m_BaseLoadAddress + m_ImageSize)
							{
								disAsm.EIP = target;
								disAsm.VirtualAddr = target;
							}
							else
							{
								return NULL;
							}
						}
						else
						{
							auto target = disAsm.Instruction.AddrValue;
							if ((ULONG_PTR)m_BaseLoadAddress <= target && target < (ULONG_PTR)m_BaseLoadAddress + m_ImageSize)
							{
								disAsm.EIP = target;
								disAsm.VirtualAddr = target;
							}
							else
							{
								return NULL;
							}
						}

						sum = 0;
						continue;
					}
					}
					disAsm.EIP += len;
					disAsm.VirtualAddr += len;
					sum += len;
					break;
				}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DrvKit_ReportException("An exception occurred! Exception code = %I32X\n", GetExceptionCode());
		}

		if (limit >= 0xFFF)
		{
			DrvKit_ReportError("Failure due to exceed the limit\n");
			return NULL;
		}
		else if (disAsm.Error < 0)
		{
			DrvKit_ReportError("Failure due to decode unsuccessfully.\n");
			return NULL;
		}
		*DecodeLen = sum;
		return (PVOID)(disAsm.EIP - sum);
	}

	VOID DrvKit_HookEng::SetBitWidth(BOOLEAN IsWow64)
	{
		m_prvIsWow64 = IsWow64;
	}

	PNT_CREATESECTION_PAYLOAD DrvKit_HookEng::GenNtCreateSectionCode(PVOID FuncAddr, PSIZE_T CodeSize)
	{
		UCHAR trampoline64[14] = { 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
		UCHAR trampoline32[5] = { 0xE9,0,0,0,0 };
		PNT_CREATESECTION_PAYLOAD pShellcode = NULL;
		ULONG ulPatchSize;

		FuncAddr = SkipBranchIns(FuncAddr, &ulPatchSize);

		*CodeSize =
			sizeof(NT_CREATESECTION_PAYLOAD) +
			ulPatchSize;
		pShellcode = (PNT_CREATESECTION_PAYLOAD)
			DrvKit_Misc::AllocateUserMemory(
				NtCurrentProcess(),
				*CodeSize);
		if (pShellcode == NULL)
		{
			DrvKit_ReportError("Failed alloc memory.\n");
			goto end;
		}

		if (m_prvIsWow64)
		{
			RtlCopyMemory(
				pShellcode->Code.Shellcode32.GetCurrentTid,
				"\x64\xA1\x18\x00\x00\x00\x8B\x40\x24",
				9);

			RtlCopyMemory(
				pShellcode->Code.Shellcode32.CompareTid,
				"\x39\x05\x00\x00\x00\x00",
				6);

			*(PULONG)(pShellcode->Code.Shellcode32.CompareTid + 2) = (ULONG)&pShellcode->Data.Tid;

			pShellcode->Code.Shellcode32.CondRelJmp[0] = 0x75;
			pShellcode->Code.Shellcode32.CondRelJmp[1] = 0x17;

			pShellcode->Code.Shellcode32.SaveEbx[0] = 0x53;

			RtlCopyMemory(
				pShellcode->Code.Shellcode32.GetSectionHandle,
				"\xA1\x00\x00\x00\x00",
				5);
			*(PULONG)(pShellcode->Code.Shellcode32.GetSectionHandle + 1) =
				(ULONG)&pShellcode->Data.SectionHandle;

			RtlCopyMemory(
				pShellcode->Code.Shellcode32.SetSectionHandle,
				"\x8B\x5C\x24\x08\x89\x03",
				6);

			RtlCopyMemory(
				pShellcode->Code.Shellcode32.Clear,
				"\x83\x25\x00\x00\x00\x00\x00",
				7);
			*(PULONG)(pShellcode->Code.Shellcode32.Clear + 2) =
				(ULONG)&pShellcode->Data.Tid;

			RtlCopyMemory(
				pShellcode->Code.Shellcode32.Epilogue,
				"\x31\xC0\x5B\xC3",
				4);

			RtlCopyMemory(
				pShellcode->Code.Shellcode32.SaveOrignCode,
				FuncAddr,
				ulPatchSize);

			*(PLONG)(trampoline32 + 1) =
				(LONG)FuncAddr +
				ulPatchSize -
				((LONG)pShellcode->Code.Shellcode32.SaveOrignCode +
				ulPatchSize) -
				sizeof(trampoline32);

			RtlCopyMemory(
				pShellcode->Code.Shellcode32.SaveOrignCode +
				ulPatchSize,
				trampoline32,
				sizeof(trampoline32));

			return pShellcode;
		}
		else
		{
			RtlCopyMemory(
				pShellcode->Code.Shellcode64.GetCurrentTid,
				"\x65\x48\x8B\x04\x25\x30\x00\x00\x00\x8B\x40\x48",
				12);

			// cmp eax,[rip+xxx]
			pShellcode->Code.Shellcode64.CompareTid[0] = 0x3B;
			pShellcode->Code.Shellcode64.CompareTid[1] = 0x05;
			*(PLONG)(pShellcode->Code.Shellcode64.CompareTid + 2) =
				(LONG)&pShellcode->Data.Tid - 
				(LONG)&pShellcode->Code.Shellcode64.CompareTid -
				sizeof(pShellcode->Code.Shellcode64.CompareTid);


			pShellcode->Code.Shellcode64.CondRelJmp[0] = 0x75;
			pShellcode->Code.Shellcode64.CondRelJmp[1] = 0x16;

			// mov rax,qword ptr:[rip+xxx]
			RtlCopyMemory(
				pShellcode->Code.Shellcode64.GetSectionHandle,
				"\x48\x8B\x05",
				3);
			*(PLONG)(pShellcode->Code.Shellcode64.GetSectionHandle + 3) =
				(LONG)&pShellcode->Data.SectionHandle - 
				(LONG)&pShellcode->Code.Shellcode64.GetSectionHandle - 
				sizeof(pShellcode->Code.Shellcode64.GetSectionHandle);
			// mov [rcx],rax
			RtlCopyMemory(
				pShellcode->Code.Shellcode64.SetSectionHandle,
				"\x48\x89\x01",
				3);

			// and dword ptr:[rip+xxx],0
			RtlCopyMemory(
				pShellcode->Code.Shellcode64.Clear,
				"\x48\x83\x25",
				3);
			*(PLONG)(pShellcode->Code.Shellcode64.Clear + 3) =
				(LONG)&pShellcode->Data.Tid - 
				(LONG)&pShellcode->Code.Shellcode64.Clear -
				sizeof(pShellcode->Code.Shellcode64.Clear);

			RtlCopyMemory(
				pShellcode->Code.Shellcode64.Epilogue,
				"\x48\x31\xC0\xC3",
				4);
			RtlCopyMemory(
				pShellcode->Code.Shellcode64.SaveOrignCode,
				FuncAddr, 
				ulPatchSize);

			FixRelativeAddress(
				FuncAddr,
				pShellcode->Code.Shellcode64.SaveOrignCode,
				ulPatchSize);

			*(PULONG_PTR)(trampoline64 + 6) = 
				(ULONG_PTR)FuncAddr + 
				ulPatchSize;
			RtlCopyMemory(
				pShellcode->Code.Shellcode64.SaveOrignCode +
				ulPatchSize,
				trampoline64, 
				sizeof(trampoline64));

			return pShellcode;
		}
		

	end:
		return NULL;
	}

	PNT_TESTALERT_PAYLOAD DrvKit_HookEng::GenNtTestAlertCode(PVOID FuncAddr, PSIZE_T CodeSize)
	{
		UCHAR trampoline64[14] = { 0xFF,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
		UCHAR trampoline32[5] = { 0xE9,0,0,0,0 };
		PNT_TESTALERT_PAYLOAD pShellcode = NULL;
		ULONG ulPatchSize;

		FuncAddr = SkipBranchIns(FuncAddr, &ulPatchSize);

		*CodeSize =
			sizeof(PNT_TESTALERT_PAYLOAD) +
			ulPatchSize;
		pShellcode = (PNT_TESTALERT_PAYLOAD)
			DrvKit_Misc::AllocateUserMemory(
				NtCurrentProcess(),
				*CodeSize);
		if (pShellcode == NULL)
		{
			DrvKit_ReportError("Failed alloc memory.\n");
			goto end;
		}

		if (m_prvIsWow64)
		{
			pShellcode->Code.Shellcode32.CallRoutine[0] = 0xff;
			pShellcode->Code.Shellcode32.CallRoutine[1] = 0x15;
			*(PULONG)(pShellcode->Code.Shellcode32.CallRoutine + 2) = (ULONG)&pShellcode->Data.LoadShellCode;

			RtlCopyMemory(
				pShellcode->Code.Shellcode32.SaveOrignCode,
				FuncAddr,
				ulPatchSize);

			*(PLONG)(trampoline32 + 1) =
				(LONG)FuncAddr +
				ulPatchSize -
				((LONG)pShellcode->Code.Shellcode32.SaveOrignCode +
					ulPatchSize) -
				sizeof(trampoline32);

			RtlCopyMemory(
				pShellcode->Code.Shellcode32.SaveOrignCode,
				FuncAddr,
				ulPatchSize);

			RtlCopyMemory(
				(PUCHAR)&pShellcode->Code.Shellcode32.SaveOrignCode + ulPatchSize,
				trampoline32,
				sizeof(trampoline32));

			return pShellcode;
		}
		else
		{
			pShellcode->Code.Shellcode64.CallRoutine[0] = 0xFF;
			pShellcode->Code.Shellcode64.CallRoutine[1] = 0x15;

			*(PLONG)(pShellcode->Code.Shellcode64.CallRoutine + 2) =
				(LONG64)&pShellcode->Data.LoadShellCode -
				(LONG64)&pShellcode->Code.Shellcode64.CallRoutine -
				sizeof(pShellcode->Code.Shellcode64.CallRoutine);

			RtlCopyMemory(
				pShellcode->Code.Shellcode64.SaveOrignCode,
				FuncAddr,
				ulPatchSize);

			FixRelativeAddress(
				FuncAddr, 
				pShellcode->Code.Shellcode64.SaveOrignCode, 
				ulPatchSize);

			*(PULONG_PTR)(trampoline64 + 6) =
				(ULONG_PTR)FuncAddr +
				ulPatchSize;

			RtlCopyMemory(
				pShellcode->Code.Shellcode64.SaveOrignCode +
				ulPatchSize,
				trampoline64,
				sizeof(trampoline64));

			return pShellcode;
		}

	end:
		return NULL;
	}

	NTSTATUS DrvKit_HookEng::UnHook()
	{
		SIZE_T protSize = 0x20;
		SIZE_T writtenSize;
		NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
		PUCHAR pTargetAddress = m_prvPatchAddress;
		ULONG ulOldProt;

		if (m_prvPatchAddress == NULL)
		{
			return STATUS_SUCCESS;
		}

		__try
		{
			ntStatus = DrvKit_Private::m_pfnZwProtectVirtualMemory(
				NtCurrentProcess(),
				(PVOID*)&pTargetAddress,
				&protSize,
				PAGE_EXECUTE_READWRITE,
				&ulOldProt);

			if (NT_SUCCESS(ntStatus))
			{
				ntStatus = DrvKit_Misc::WriteUserMemory(
					NtCurrentProcess(),
					m_prvPatchAddress,
					m_prvSaveByteCode,
					sizeof(m_prvSaveByteCode));

				if (!NT_SUCCESS(ntStatus))
				{
					DrvKit_ReportError("Can't patch address: %p\n", pTargetAddress);
					goto end;
				}

				ntStatus = DrvKit_Private::m_pfnZwFlushInstructionCache(
					NtCurrentProcess(),
					m_prvPatchAddress,
					sizeof(m_prvSaveByteCode));

				if (!NT_SUCCESS(ntStatus))
				{
					DrvKit_ReportError("Can't flush instruction -- Error code: %I32x\n", ntStatus);
					goto end;
				}

				DrvKit_Private::m_pfnZwProtectVirtualMemory(
					NtCurrentProcess(),
					(PVOID*)&pTargetAddress,
					&protSize,
					ulOldProt,
					&ulOldProt);

				if (m_prvTrampoline)
				{
					DrvKit_Misc::ReleaseUserMemory(
						ZwCurrentProcess(),
						(PVOID*)&m_prvTrampoline,
						m_prvTrampolineSize);
				}
				
			}

		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DrvKit_ReportException("An exception occurred.\n");
		}

	end:

		return ntStatus;
	}
};


