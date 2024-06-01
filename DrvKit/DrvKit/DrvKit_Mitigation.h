#pragma once
#include "prefix.h"

namespace DK
{
	class DrvKit_Mitigation
	{
	private:
		DrvKit_Mitigation();
		~DrvKit_Mitigation();

	public:
		static NTSTATUS SetProcessMitigationPolicy(
			_In_ HANDLE ProcessId,
			_In_ _PROCESS_MITIGATION_POLICY Class,
			_In_ PVOID NewPolicy,
			_Inout_opt_ PVOID OldPolicy = NULL);

		static NTSTATUS GetProcessMitigationPolicy(
			_In_ PEPROCESS Process,
			_In_ _PROCESS_MITIGATION_POLICY Class,
			_In_ PVOID Policy);
	};
};