#pragma once
#include "prefix.h"

#define MAX_NUM_OF_PARAM 64

namespace DK
{

#pragma pack(push,1)
	typedef struct _CALL_SHELLCODE32
	{
			UCHAR Prologue[9];
			UCHAR StackPassArg[MAX_NUM_OF_PARAM][5];
			UCHAR Call[6];
			UCHAR SaveRetValueCode[5];
			UCHAR CompleteCode[7];
			UCHAR Epilogue[8];
	}CALL_SHELLCODE32, * PCALL_SHELLCODE32;

	typedef struct _CALL_SHELLCODE64
	{
		UCHAR Prologue[24];
		UCHAR RegPassArgv[4][10];
		UCHAR StackPassArg[MAX_NUM_OF_PARAM - 4][0x12];
		UCHAR Call[6];
		UCHAR SaveRetValueCode[7];
		UCHAR CompleteCode[7];
		UCHAR Epilogue[25];
	}CALL_SHELLCODE64, * PCALL_SHELLCODE64;

	typedef struct _CALL_PAYLOAD
	{
		struct
		{
			PVOID FunctionAddress;
			BOOLEAN Completed;
			PVOID RetValue;
		}Data;

		union 
		{
			CALL_SHELLCODE32 Shellcode32;
			CALL_SHELLCODE64 Shellcode64;
		}Code;
	}CALL_PAYLOAD,*PCALL_PAYLOAD;
#pragma pack(pop)

	class DrvKit_UserCall
	{
	private:
		DrvKit_UserCall();
		~DrvKit_UserCall();

		static BOOLEAN DoCallUser(_In_ PVOID Payload);
		static VOID PackParam(
			_In_ BOOLEAN Wow64,
			_Inout_ PCALL_PAYLOAD CallPayload,
			_In_ PVOID Func,
			_In_ ULONG Argc,
			_In_ va_list param);
	public:
		
		static PVOID UserModeCall(
			_In_ PVOID Func,
			_In_ ULONG Argc,
			_In_ PVOID Argv,
			...);
	};
};