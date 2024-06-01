#pragma once
#include "prefix.h"
#include "DrvKit_Public.h"
#include <vector>

namespace DK
{
	class DrvKit_Control
	{
	private:
		static SHORT m_CancelLoadWhileCreating;
		static PDEVICE_OBJECT m_DevObj;
		static UNICODE_STRING m_DesiredProcess;
		static std::vector<PWCHAR>* m_InjectList;
		static ERESOURCE m_InjectRWLock;
		static WCHAR m_Buf[MAX_PATH_SIZE];
	private:
		DrvKit_Control();
		~DrvKit_Control();

		static NTSTATUS DevDispatcher(PDEVICE_OBJECT DevObj, PIRP Irp);
		static VOID LdrNotify(
			_In_opt_ PUNICODE_STRING FullImageName,
			_In_ HANDLE ProcessId,
			_In_ PIMAGE_INFO ImageInfo,
			_Inout_ PBOOLEAN Next);
		static BOOLEAN IsSpecialProcess(HANDLE ProcessId);
		static BOOLEAN WhetherItsTimeToLoadDll(PUNICODE_STRING FullImageName);

	public:
		static NTSTATUS Init(PDRIVER_OBJECT DrvObj);
		static VOID UnInit();
		static BOOLEAN SetDesiredProcess(PWCHAR ProcessPath);
		static BOOLEAN InsertInjectList(PWCHAR DllPath);
		static VOID RemoveInjectList(PWCHAR DllPath);
		static VOID ReleaseInjectList();
	};
};
