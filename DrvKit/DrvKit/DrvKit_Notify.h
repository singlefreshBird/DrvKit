#pragma once
#include "prefix.h"
#include <vector>

namespace DK
{
	using PMODULE_LOAD_NOTIFY_CALLBACK = VOID(*)(
		_In_opt_ PUNICODE_STRING FullImageName,
		_In_ HANDLE ProcessId,                
		_In_ PIMAGE_INFO ImageInfo,
		_Inout_ PBOOLEAN Next);

	using PPROCESS_CREATE_NOTIFY_CALLBACK = VOID(*)(
		_In_ HANDLE ParentId,
		_In_ HANDLE ProcessId,
		_In_ BOOLEAN Create,
		_In_opt_ PBOOLEAN Next);

	typedef enum _Notify_Type
	{
		eLdrNotify = 1,				// ģ������¼��ص�
		eProcessNotify = 2,			// ���̴����˳��¼��ص�
		eThreadNotify = 4,			// �̴߳����˳��¼��ص�
		eRegNotify = 8				// ע�������¼��ص�
	}Notify_Type;

	class DrvKit_Notify
	{
	private:
		static BOOLEAN m_Inited;
		static ERESOURCE m_LdrListRWLock;
		static ERESOURCE m_ProcListRWLock;
		static std::vector<PMODULE_LOAD_NOTIFY_CALLBACK>* m_LdrNotifyList;
		static std::vector<PPROCESS_CREATE_NOTIFY_CALLBACK>* m_ProcNotifyList;

	private:
		DrvKit_Notify();
		~DrvKit_Notify();

		static VOID LdrNotify(
			_In_opt_ PUNICODE_STRING FullImageName,
			_In_ HANDLE ProcessId,
			_In_ PIMAGE_INFO ImageInfo
		);

		static VOID ProcessNotify(
			_In_ HANDLE ParentId,
			_In_ HANDLE ProcessId,
			_In_ BOOLEAN Create
		);
		 
	public:
		static NTSTATUS Init(Notify_Type Type);
		static NTSTATUS RegisterModuleLoadNotify(PMODULE_LOAD_NOTIFY_CALLBACK NotifyCallback);
		static VOID DegisterModuleLoadNotify(PMODULE_LOAD_NOTIFY_CALLBACK NotifyCallback);
		static NTSTATUS RegisterProcessCreateNotify(PPROCESS_CREATE_NOTIFY_CALLBACK NotifyCallback);
		static VOID DegisterProcessCreateNotify(PPROCESS_CREATE_NOTIFY_CALLBACK NotifyCallback);
		static VOID UnInit();
	};
};


