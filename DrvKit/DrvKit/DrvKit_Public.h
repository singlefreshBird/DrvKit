#pragma once

#define DEVICE_NAME L"\\Device\\DrvKit"
#define KERNEL_SYMBOLIC_LINK_NAME L"\\??\\DrvKit"
#define USER_SYMBOLIC_LINK_NAME L"\\\\.\\DrvKit"

#define _CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

#define IOCTL_DRVKIT_CONTROL _CTL_CODE(0x00000022,0x801,0,3)

#define MAX_PATH_SIZE 260

typedef enum _OPERTION
{
	eOption_LoadDllToExistingProcess = 0,
	eOption_SetCreatingProcessPath,
	eOption_CancelLoadingCreatingProcess,
	eOption_RemoveDllItem,
	eOption_AddDllItem,
	eOption_ClearAllDllItem,
	eOption_LoadDll,
	eOption_UnloadDll
}OPERTION;

#pragma pack(push,4)
typedef struct _DK_CMD
{
	OPERTION Opertion;
	union 
	{
		struct 
		{
			wchar_t ProcessPath[MAX_PATH_SIZE];
		}LOAD_CREATING_PROCESS_CMDLINE;

		struct 
		{
			wchar_t DllPath[MAX_PATH_SIZE];
		}REMOVE_DLL_ITEM_CMDLINE;

		struct 
		{
			wchar_t DllPath[MAX_PATH_SIZE];
		}ADD_DLL_ITEM;

		struct
		{
			unsigned long ProcessId;
			wchar_t DllPath[MAX_PATH_SIZE];
		}LOAD_DLL;

		struct
		{
			short Value;
		}CANCEL_LOAD_CREATING_PROCESS_CMDLINE;

		struct
		{
			bool Force;
			unsigned long ProcessId;
			unsigned long long LoadBaseAddress;
		}UNLOAD_DLL;

	}Cmd;
}DK_CMD,*PDK_CMD;
#pragma pack(pop)