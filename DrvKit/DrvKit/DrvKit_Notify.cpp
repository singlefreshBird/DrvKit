#include "DrvKit_Notify.h"
//#include <>

namespace DK
{
	std::vector<PMODULE_LOAD_NOTIFY_CALLBACK>* DrvKit_Notify::m_LdrNotifyList;
	std::vector<PPROCESS_CREATE_NOTIFY_CALLBACK>* DrvKit_Notify::m_ProcNotifyList;
	BOOLEAN DrvKit_Notify::m_Inited = FALSE;
	ERESOURCE DrvKit_Notify::m_LdrListRWLock;
	ERESOURCE DrvKit_Notify::m_ProcListRWLock;

	DrvKit_Notify::DrvKit_Notify() {}
	DrvKit_Notify::~DrvKit_Notify() {}

	VOID DrvKit_Notify::LdrNotify(
		_In_opt_ PUNICODE_STRING FullImageName,
		_In_ HANDLE ProcessId,
		_In_ PIMAGE_INFO ImageInfo
	)
	{
		BOOLEAN bNext = TRUE;
		ExAcquireResourceSharedLite(&m_LdrListRWLock,TRUE);

		for (auto item : *m_LdrNotifyList)
		{
			item(FullImageName, ProcessId, ImageInfo, &bNext);
			if (!bNext) break;
		}

		ExReleaseResourceLite(&m_LdrListRWLock);
	}

	VOID DrvKit_Notify::ProcessNotify(
		_In_ HANDLE ParentId,
		_In_ HANDLE ProcessId,
		_In_ BOOLEAN Create
	)
	{
		BOOLEAN bNext = TRUE;
		if (!Create)
		{
			ExAcquireResourceSharedLite(&m_ProcListRWLock, TRUE);
			for (auto item : *m_ProcNotifyList)
			{
				item(ParentId, ProcessId, Create, &bNext);
				if (!bNext) break;
			}
			ExReleaseResourceLite(&m_ProcListRWLock);
		}
	}

	NTSTATUS DrvKit_Notify::Init(Notify_Type Type)
	{
		if (m_Inited) return STATUS_SUCCESS;
		NTSTATUS ntStatus = ExInitializeResourceLite(&m_LdrListRWLock);
		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("Failed to init RWLock.\n");
			goto end;
		}

		ntStatus = ExInitializeResourceLite(&m_ProcListRWLock);
		if (!NT_SUCCESS(ntStatus))
		{
			DrvKit_ReportError("Failed to init RWLock.\n");
			goto end;
		}

		m_LdrNotifyList = new std::vector<PMODULE_LOAD_NOTIFY_CALLBACK>;
		if (m_LdrNotifyList == NULL) goto end;

		m_ProcNotifyList = new std::vector<PPROCESS_CREATE_NOTIFY_CALLBACK>;
		if (m_ProcNotifyList == NULL) goto end;

		if (FlagOn(Type, eLdrNotify))
		{
			ntStatus = PsSetLoadImageNotifyRoutine(LdrNotify);
			if (!NT_SUCCESS(ntStatus))
			{
				DrvKit_ReportError("Failed to PsSetLoadImageNotifyRoutine.\n");
				goto end;
			}
		}
		
		if (FlagOn(Type, eProcessNotify))
		{
			ntStatus = PsSetCreateProcessNotifyRoutine(ProcessNotify, FALSE);
			if (!NT_SUCCESS(ntStatus))
			{
				DrvKit_ReportError("Failed to PsSetCreateProcessNotifyRoutine. Code = %I32X\n",ntStatus);
				goto end;
			}
		}

		InterlockedExchange8((char*)&m_Inited, TRUE);

	end:
		if (!NT_SUCCESS(ntStatus))
		{
			PsRemoveLoadImageNotifyRoutine(LdrNotify);
		}
		return ntStatus;
	}

	VOID DrvKit_Notify::UnInit()
	{
		if (InterlockedExchange8((char*)&m_Inited, FALSE))
		{
			PsRemoveLoadImageNotifyRoutine(LdrNotify);
			PsSetCreateProcessNotifyRoutine(ProcessNotify, TRUE);
			delete m_LdrNotifyList;
			delete m_ProcNotifyList;
			ExDeleteResourceLite(&m_LdrListRWLock);
			ExDeleteResourceLite(&m_ProcListRWLock);
		}
	}

	NTSTATUS DrvKit_Notify::RegisterModuleLoadNotify(PMODULE_LOAD_NOTIFY_CALLBACK NotifyCallback)
	{
		if (!m_Inited) return STATUS_UNSUCCESSFUL;
		if (NotifyCallback == NULL) return STATUS_INVALID_PARAMETER;

		ExAcquireResourceExclusiveLite(&m_LdrListRWLock, TRUE);
		m_LdrNotifyList->push_back(NotifyCallback);
		ExReleaseResourceLite(&m_LdrListRWLock);

		return STATUS_SUCCESS;
	}

	VOID DrvKit_Notify::DegisterModuleLoadNotify(PMODULE_LOAD_NOTIFY_CALLBACK NotifyCallback)
	{
		if (!m_Inited) return;
		if (NotifyCallback)
		{
			ExAcquireResourceExclusiveLite(&m_LdrListRWLock, TRUE);
			for (auto it = m_LdrNotifyList->begin(); it != m_LdrNotifyList->end();)
			{
				if (*it == NotifyCallback)
				{
					it = m_LdrNotifyList->erase(it);
					break;
				}
			}
			ExReleaseResourceLite(&m_LdrListRWLock);
		}
	}

	NTSTATUS DrvKit_Notify::RegisterProcessCreateNotify(PPROCESS_CREATE_NOTIFY_CALLBACK NotifyCallback)
	{
		if (!m_Inited) return STATUS_UNSUCCESSFUL;
		if (NotifyCallback == NULL) return STATUS_INVALID_PARAMETER;

		ExAcquireResourceExclusiveLite(&m_ProcListRWLock, TRUE);
		m_ProcNotifyList->push_back(NotifyCallback);
		ExReleaseResourceLite(&m_ProcListRWLock);

		return STATUS_SUCCESS;
	}

	VOID DrvKit_Notify::DegisterProcessCreateNotify(PPROCESS_CREATE_NOTIFY_CALLBACK NotifyCallback)
	{
		if (!m_Inited) return;
		if (NotifyCallback)
		{
			ExAcquireResourceExclusiveLite(&m_ProcListRWLock, TRUE);
			for (auto it = m_ProcNotifyList->begin(); it != m_ProcNotifyList->end();)
			{
				if (*it == NotifyCallback)
				{
					it = m_ProcNotifyList->erase(it);
					break;
				}
			}
			ExReleaseResourceLite(&m_ProcListRWLock);
		}
	}
};