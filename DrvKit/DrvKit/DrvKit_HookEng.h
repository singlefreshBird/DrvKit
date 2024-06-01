#pragma once
#include "prefix.h"

#define MAX_INSTRUCTIONS 16

namespace DK
{
#pragma pack(1)
	typedef struct _NT_CREATESECTION_CODE32
	{
		UCHAR GetCurrentTid[9];
		UCHAR CompareTid[6];
		UCHAR CondRelJmp[2];
		UCHAR SaveEbx[1];
		UCHAR GetSectionHandle[5];
		UCHAR SetSectionHandle[6];
		UCHAR Clear[7];
		UCHAR Epilogue[4];
		UCHAR SaveOrignCode[1];
	}NT_CREATESECTION_CODE32,*PNT_CREATESECTION_CODE32;

	typedef struct _NT_CREATESECTION_CODE64
	{
		UCHAR GetCurrentTid[12];
		UCHAR CompareTid[6];
		UCHAR CondRelJmp[2];
		UCHAR GetSectionHandle[7];
		UCHAR SetSectionHandle[3];
		UCHAR Clear[8];
		UCHAR Epilogue[4];
		UCHAR SaveOrignCode[1];
	}NT_CREATESECTION_CODE64,*PNT_CREATESECTION_CODE64;

	typedef struct _NT_CREATESECTION_PAYLOAD
	{
		struct
		{
			ULONG Tid;
			HANDLE SectionHandle;
		}Data;

		union 
		{
			NT_CREATESECTION_CODE32 Shellcode32;
			NT_CREATESECTION_CODE64 Shellcode64;
		}Code;
	}NT_CREATESECTION_PAYLOAD,*PNT_CREATESECTION_PAYLOAD;
	
	typedef struct _NT_TESTALERT_CODE32
	{
		UCHAR CallRoutine[6];
		UCHAR SaveOrignCode[1];
	}NT_TESTALERT_CODE32,*PNT_TESTALERT_CODE32;

	typedef struct _NT_TESTALERT_CODE64
	{
		UCHAR CallRoutine[6];
		UCHAR SaveOrignCode[1];
	}NT_TESTALERT_CODE64, * PNT_TESTALERT_CODE64;

	typedef struct _NT_TESTALERT_PAYLOAD
	{
		struct
		{
			ULONG Tid;
			PVOID LoadShellCode;
		}Data;
		union
		{
			NT_TESTALERT_CODE32 Shellcode32;
			NT_TESTALERT_CODE64 Shellcode64;
		}Code;
	}NT_TESTALERT_PAYLOAD, * PNT_TESTALERT_PAYLOAD;
#pragma pack()

	class DrvKit_HookEng
	{
	private:
		PVOID m_BaseLoadAddress;
		SIZE_T m_ImageSize;
		UCHAR m_prvSaveByteCode[14];
		PUCHAR m_prvPatchAddress;
		PUCHAR m_prvTrampoline;
		SIZE_T m_prvTrampolineSize;
		BOOLEAN m_prvIsWow64;
	private:
		VOID FixRelativeAddress(PVOID Address, PVOID NewBaseAddress, ULONG Size);
		PVOID AllocTrampoline(PVOID TargetFunc,PVOID ProxyFunc, ULONG Size);
		PVOID SkipBranchIns(PVOID Address, PULONG DecodeLen);
	public:
		DrvKit_HookEng(PVOID BaseLoadAddress, SIZE_T ImageSize);
		DrvKit_HookEng(PVOID BaseLoadAddress, SIZE_T ImageSize, BOOLEAN IsWow64);
		~DrvKit_HookEng();

		VOID SetBitWidth(BOOLEAN IsWow64);
		PNT_CREATESECTION_PAYLOAD GenNtCreateSectionCode(PVOID FuncAddr,PSIZE_T CodeSize);
		PNT_TESTALERT_PAYLOAD GenNtTestAlertCode(PVOID FuncAddr,PSIZE_T CodeSize);
		NTSTATUS Hook(PVOID TargetFunc, PVOID ProxyFunc, PVOID* OldFunc);
		NTSTATUS UnHook();
	};
};