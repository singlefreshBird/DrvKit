#include "prefix.h"
#include "DrvKit_Control.h"
#include "DrvKit_Misc.h"
#include <unordered_map>


using namespace DK;

VOID DrvKit_DriverUnload(_In_ PDRIVER_OBJECT DrvObj);

extern"C"
NTSTATUS 
DriverEntry(
	_In_ PDRIVER_OBJECT DrvObj,
	_In_ PUNICODE_STRING RegPath)
{
	NTSTATUS ntStatus;
	DrvObj->DriverUnload = DrvKit_DriverUnload;
	
	ntStatus = DrvKit_Control::Init(DrvObj);
	
	return STATUS_SUCCESS;
}

VOID DrvKit_DriverUnload(_In_ PDRIVER_OBJECT DrvObj)
{
	DrvKit_Control::UnInit();

	DbgPrint("[+] DriverUnload.\n");
}


