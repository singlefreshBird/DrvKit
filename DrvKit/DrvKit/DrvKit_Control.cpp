#include "DrvKit_Control.h"
#include "DrvKit_Notify.h"
#include "DrvKit_Loader.h"
#include "DrvKit_Private.h"
#include "DrvKit_Misc.h"
#include "DrvKit_Public.h"

namespace DK
{
	SHORT DrvKit_Control::m_CancelLoadWhileCreating = 1;
	PDEVICE_OBJECT DrvKit_Control::m_DevObj = NULL;
	std::vector<PWCHAR>* DrvKit_Control::m_InjectList = NULL;
	ERESOURCE DrvKit_Control::m_InjectRWLock;
	UNICODE_STRING DrvKit_Control::m_DesiredProcess;
	WCHAR DrvKit_Control::m_Buf[MAX_PATH_SIZE];

	NTSTATUS DrvKit_Control::Init(PDRIVER_OBJECT DrvObj)
	{
		NTSTATUS ntStatus;

		__try
		{
			ntStatus = DrvKit_Misc::Init();
			if (!NT_SUCCESS(ntStatus))
			{
				__leave;
			}

			if (!DrvKit_Misc::IsSystemSupported())
			{
				DrvKit_ReportError("The system is not supported.\n");
				__leave;
			}

			ntStatus = ExInitializeResourceLite(&m_InjectRWLock);
			if (!NT_SUCCESS(ntStatus))
			{
				DrvKit_ReportError("Failed to init lock. Code = %I32X\n", ntStatus);
				return FALSE;
			}

			ntStatus = DrvKit_Private::Init();
			if (!NT_SUCCESS(ntStatus))
			{
				DrvKit_ReportError("The system is not supported.\n");
				__leave;
			}

			m_InjectList = new std::vector<PWCHAR>;
			if (m_InjectList == NULL) __leave;

			ntStatus = DrvKit_Notify::Init(eLdrNotify);
			if (!NT_SUCCESS(ntStatus))
			{
				DrvKit_ReportError("Can't register notify callback.\n");
				__leave;
			}

			if (!DrvKit_Loader::Init())
			{
				DrvKit_ReportError("Failed to init loader.\n");
				__leave;
			}

			ntStatus = DrvKit_Notify::RegisterModuleLoadNotify(LdrNotify);
			if (!NT_SUCCESS(ntStatus))
			{
				DrvKit_ReportError("Can't add module loading notify callback.\n");
				__leave;
			}

			UNICODE_STRING usDevName;
			RtlInitUnicodeString(&usDevName, DEVICE_NAME);
			// 创建新设备对象，用于通信
			ntStatus = IoCreateDevice(DrvObj, 0, &usDevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &m_DevObj);
			if (!NT_SUCCESS(ntStatus))
			{
				DrvKit_ReportError("Failed to create device object. Code = %I32X\n",ntStatus);
				__leave;
			}

			UNICODE_STRING usSymblk;
			RtlInitUnicodeString(&usSymblk, KERNEL_SYMBOLIC_LINK_NAME);
			// 创建符号链接
			ntStatus = IoCreateSymbolicLink(&usSymblk, &usDevName);
			if (!NT_SUCCESS(ntStatus))
			{
				DrvKit_ReportError("Failed to create symbolic link. Code = %I32X\n", ntStatus);
				__leave;
			}

			for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
			{
				DrvObj->MajorFunction[i] = DrvKit_Control::DevDispatcher;
			}

			// 清除初始化标志
			DrvObj->DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
			// 设置为缓冲IO方式与应用层交换数据
			DrvObj->DeviceObject->Flags |= DO_BUFFERED_IO;
		}
		__finally
		{
			if (!NT_SUCCESS(ntStatus))
			{
				if (m_InjectList)
				{
					delete m_InjectList;
					m_InjectList = NULL;
				}

				DrvKit_Notify::UnInit();
				DrvKit_Loader::UnInit();
			}
		}

		return ntStatus;
	}

	VOID DrvKit_Control::UnInit()
	{
		DrvKit_Notify::UnInit();
		DrvKit_Loader::UnInit();

		ReleaseInjectList();

		UNICODE_STRING usSymblk;
		RtlInitUnicodeString(&usSymblk, KERNEL_SYMBOLIC_LINK_NAME);
		IoDeleteSymbolicLink(&usSymblk);
		IoDeleteDevice(m_DevObj);
	}

	VOID DrvKit_Control::LdrNotify(
		_In_opt_ PUNICODE_STRING FullImageName,
		_In_ HANDLE ProcessId,
		_In_ PIMAGE_INFO ImageInfo,
		_Inout_ PBOOLEAN Next)
	{
		if (ProcessId == (HANDLE)4 || 
			KeGetCurrentIrql() > APC_LEVEL || // 注入工作是放在劳务线程中进行的，因此Irql可以在APC_LEVEL进行
			FullImageName == NULL) return;

		if (InterlockedCompareExchange16((SHORT*)&m_CancelLoadWhileCreating, 1, 1)) return;
		

		PVOID pLoadBaseAddr = NULL;

		ExAcquireResourceSharedLite(&m_InjectRWLock, TRUE);

		if (IsSpecialProcess(ProcessId))
		{
			// 注入新创建的进程时机需要在ntdll加载后
			if (WhetherItsTimeToLoadDll(FullImageName))
			{
				for (auto item : *m_InjectList)
				{
					DrvKit_Loader::LoadDll(
						(ULONG)ProcessId,
						item,
						&pLoadBaseAddr,
						ImageInfo->ImageBase);
				}
			}
		}

		ExReleaseResourceLite(&m_InjectRWLock);
	}


	BOOLEAN DrvKit_Control::IsSpecialProcess(HANDLE ProcessId)
	{
		PEPROCESS pProcess = NULL;
		PUNICODE_STRING pProcName = NULL;
		BOOLEAN bRet = FALSE;

		NTSTATUS ntStatus = PsLookupProcessByProcessId(ProcessId, &pProcess);
		if (NT_SUCCESS(ntStatus))
		{
			ntStatus = SeLocateProcessImageName(pProcess, &pProcName);
			if (NT_SUCCESS(ntStatus))
			{
				ExAcquireResourceSharedLite(&m_InjectRWLock, TRUE);
				bRet = !RtlCompareUnicodeString(pProcName, &m_DesiredProcess, TRUE);
				ExReleaseResourceLite(&m_InjectRWLock);
				ExFreePool(pProcName);
			}
			ObDereferenceObject(pProcess);
		}

		return bRet;
	}

	BOOLEAN DrvKit_Control::WhetherItsTimeToLoadDll(PUNICODE_STRING FullImageName)
	{
		const UNICODE_STRING uzDesiredModule = RTL_CONSTANT_STRING(L"*\\NTDLL.DLL");
		return FsRtlIsNameInExpression((PUNICODE_STRING)&uzDesiredModule, FullImageName, TRUE, NULL);
	}

	BOOLEAN DrvKit_Control::InsertInjectList(PWCHAR DllPath)
	{
		ULONG dwPath = wcslen(DllPath);
		PWCHAR dllPath = NULL;

		dllPath = new WCHAR[dwPath + 1];
		if (dllPath)
		{
			RtlCopyMemory(dllPath, DllPath, dwPath * sizeof(WCHAR));
			dllPath[dwPath] = 0;
			ExAcquireResourceExclusiveLite(&m_InjectRWLock, TRUE);
			m_InjectList->push_back(dllPath);
			ExReleaseResourceLite(&m_InjectRWLock);
			return TRUE;
		}

		return FALSE;
	}

	BOOLEAN DrvKit_Control::SetDesiredProcess(PWCHAR ProcessPath)
	{
		NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
		UNICODE_STRING usProcessName;
		RtlInitUnicodeString(&usProcessName, ProcessPath);

		ExAcquireResourceExclusiveLite(&m_InjectRWLock, TRUE);
		if (usProcessName.MaximumLength < sizeof(m_Buf))
		{
			RtlInitEmptyUnicodeString(&m_DesiredProcess, m_Buf, sizeof(m_Buf));
			ntStatus = DrvKit_Misc::NtPathToDevicePath(&usProcessName, &m_DesiredProcess);
		}
		ExReleaseResourceLite(&m_InjectRWLock);
		return NT_SUCCESS(ntStatus);
	}

	VOID DrvKit_Control::RemoveInjectList(PWCHAR DllPath)
	{
		ExAcquireResourceExclusiveLite(&m_InjectRWLock, TRUE);
		if (DllPath)
		{
			for (auto it = m_InjectList->begin(); it != m_InjectList->end();)
			{
				if (!_wcsicmp(*it, DllPath))
				{
					delete[] * it;
					it = m_InjectList->erase(it);
					break;
				}
				else
				{
					it++;
				}
			}
		}
		else
		{
			for (auto it = m_InjectList->begin(); it != m_InjectList->end(); it++)
			{
				delete[] *it;
			}
			m_InjectList->clear();
		}
		ExReleaseResourceLite(&m_InjectRWLock);
	}

	VOID DrvKit_Control::ReleaseInjectList()
	{
		ExAcquireResourceExclusiveLite(&m_InjectRWLock, TRUE);
		for (ULONG i=0;i<m_InjectList->size();i++)
		{
			delete[] (*m_InjectList)[i];
		}
		ExReleaseResourceLite(&m_InjectRWLock);
		delete m_InjectList;
		m_InjectList = NULL;
		ExDeleteResourceLite(&m_InjectRWLock);
	}

	NTSTATUS DrvKit_Control::DevDispatcher(PDEVICE_OBJECT DevObj, PIRP Irp)
	{
		NTSTATUS ntStatus = STATUS_SUCCESS;
		auto pIostk = IoGetCurrentIrpStackLocation(Irp);

		if (pIostk->MajorFunction == IRP_MJ_DEVICE_CONTROL)
		{
			__try
			{
				if (pIostk->Parameters.DeviceIoControl.IoControlCode == IOCTL_DRVKIT_CONTROL)
				{
					ULONG ulSize = pIostk->Parameters.DeviceIoControl.InputBufferLength;
					PDK_CMD cmd = (PDK_CMD)Irp->AssociatedIrp.SystemBuffer;


					if (cmd == nullptr)
					{
						ntStatus = STATUS_INVALID_ADDRESS;

						goto end;
					}

					if (cmd->Opertion == OPERTION::eOption_AddDllItem)
					{
						InsertInjectList(cmd->Cmd.ADD_DLL_ITEM.DllPath);
					}
					else if (cmd->Opertion == OPERTION::eOption_RemoveDllItem)
					{
						RemoveInjectList(cmd->Cmd.REMOVE_DLL_ITEM_CMDLINE.DllPath);
					}
					else if (cmd->Opertion == OPERTION::eOption_ClearAllDllItem)
					{
						RemoveInjectList(NULL);
					}
					else if (cmd->Opertion == OPERTION::eOption_SetCreatingProcessPath)
					{
						SetDesiredProcess(cmd->Cmd.LOAD_CREATING_PROCESS_CMDLINE.ProcessPath);
					}
					else if (cmd->Opertion == OPERTION::eOption_CancelLoadingCreatingProcess)
					{
						if (cmd->Cmd.CANCEL_LOAD_CREATING_PROCESS_CMDLINE.Value)
						{
							InterlockedCompareExchange16(
								(SHORT*)&m_CancelLoadWhileCreating,
								cmd->Cmd.CANCEL_LOAD_CREATING_PROCESS_CMDLINE.Value,
								0);
						}
						else
						{
							InterlockedCompareExchange16(
								(SHORT*)&m_CancelLoadWhileCreating,
								cmd->Cmd.CANCEL_LOAD_CREATING_PROCESS_CMDLINE.Value,
								1);
						}
					}
					else if (cmd->Opertion == OPERTION::eOption_LoadDll)
					{
						ntStatus = DrvKit_Loader::LoadDll(cmd->Cmd.LOAD_DLL.ProcessId, cmd->Cmd.LOAD_DLL.DllPath, NULL);
					}
					else if (cmd->Opertion == OPERTION::eOption_UnloadDll)
					{
						DrvKit_Loader::UnLoadDll(cmd->Cmd.UNLOAD_DLL.ProcessId,(PVOID)cmd->Cmd.UNLOAD_DLL.LoadBaseAddress, cmd->Cmd.UNLOAD_DLL.Force);
						ntStatus = STATUS_SUCCESS;
					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DrvKit_ReportException("Invail memory! Code = %I32X\n",GetExceptionCode());
			}
		}
		else
		{
			ntStatus = STATUS_SUCCESS;
		}
		
	end:
		Irp->IoStatus.Status = ntStatus;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return ntStatus;
	}
};