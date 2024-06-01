#include "DrvKit_Mitigation.h"

namespace DK
{
	DrvKit_Mitigation::DrvKit_Mitigation(){}
	DrvKit_Mitigation::~DrvKit_Mitigation(){}

	NTSTATUS DrvKit_Mitigation::SetProcessMitigationPolicy(
		_In_ HANDLE ProcessId,
		_In_ _PROCESS_MITIGATION_POLICY Class,
		_In_ PVOID NewPolicy,
		_Inout_opt_ PVOID OldPolicy)
	{
		NTSTATUS ntStatus;
		ULONG inPolicy[2]; 
		ULONG outPolicy[2];
		HANDLE hProcess = NULL;
		OBJECT_ATTRIBUTES oa;
		CLIENT_ID cid;
		ULONG ulReadSize;

		InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		cid.UniqueProcess = ProcessId;
		cid.UniqueThread = 0;

		hProcess = ZwCurrentProcess();
		if (Class == ProcessDynamicCodePolicy)
		{
			ntStatus = ZwOpenProcess(&hProcess, GENERIC_ALL, &oa, &cid);
			if (!NT_SUCCESS(ntStatus))
			{
				goto end;
			}
		}
		
		if (OldPolicy)
		{
			outPolicy[0] = Class;
			outPolicy[1] = 0;

			ntStatus = ZwQueryInformationProcess(
				hProcess,
				ProcessMitigationPolicy,
				&outPolicy,
				sizeof(outPolicy),
				&ulReadSize);

			*(PULONG)OldPolicy = outPolicy[1];

			if (!NT_SUCCESS(ntStatus))
			{
				DrvKit_ReportError(
					"Failed to query process info -- Status: %I32x\n",
					ntStatus);
				goto end;
			}
		}

		inPolicy[0] = Class;
		inPolicy[1] = *(PULONG)NewPolicy;

		ntStatus = ZwSetInformationProcess(
			hProcess,
			ProcessMitigationPolicy,
			&inPolicy,
			sizeof(inPolicy));
		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError(
				"Failed to set process info -- Status: %I32x\n",
				ntStatus);
			goto end;
		}

	end:

		if (hProcess && hProcess != ZwCurrentProcess())
		{
			ZwClose(hProcess);
		}

		return ntStatus;
	}
};