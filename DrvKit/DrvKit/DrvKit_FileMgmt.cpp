#include "DrvKit_FileMgmt.h"
#include "DrvKit_Misc.h"
#include <ntstrsafe.h>

namespace DK
{
	DrvKit_FileMgmt::DrvKit_FileMgmt():
		m_Buffer{0},
		m_prvFileHandle(NULL),
		m_prvFileInfo{NULL},
		m_prvFileSymbolLink{0}
	{}

	DrvKit_FileMgmt::DrvKit_FileMgmt(UNICODE_STRING FilePath):
		m_prvFileHandle(NULL),
		m_prvFileInfo{ NULL },
		m_prvFileSymbolLink{ 0 }
	{
		CovertFilePathToSymbolLinkPath(&FilePath);
	}
	
	DrvKit_FileMgmt::~DrvKit_FileMgmt()
	{
		if (m_prvFileHandle)
		{
			ZwClose(m_prvFileHandle);
		}
	}

	NTSTATUS DrvKit_FileMgmt::CovertFilePathToSymbolLinkPath(_In_ PUNICODE_STRING FilePath)
	{
		UNICODE_STRING uszPrefix = RTL_CONSTANT_STRING(L"\\??\\");
		NTSTATUS ntStatus;

		if (!FsRtlIsNameInExpression(&uszPrefix, FilePath, TRUE, NULL))
		{
			ntStatus = RtlStringCbPrintfW(m_Buffer, sizeof(m_Buffer), L"%s%s", L"\\??\\", FilePath->Buffer);
			m_prvFileSymbolLink.Buffer = m_Buffer;
			m_prvFileSymbolLink.Length = uszPrefix.Length + FilePath->Length;
			m_prvFileSymbolLink.MaximumLength = uszPrefix.Length + FilePath->MaximumLength;
		}
		else
		{
			m_prvFileSymbolLink.Buffer = m_Buffer;
			if (FilePath->MaximumLength <= sizeof(m_Buffer))
			{
				m_prvFileSymbolLink.Length = FilePath->Length;
				m_prvFileSymbolLink.MaximumLength = FilePath->MaximumLength;
				RtlCopyUnicodeString(&m_prvFileSymbolLink, FilePath);
				ntStatus = STATUS_SUCCESS;
			}
			else
			{
				ntStatus = STATUS_UNSUCCESSFUL;
			}
		}

		return ntStatus;
	}

	NTSTATUS DrvKit_FileMgmt::Open(OPEN_MODE Mode, ACCESS_MASK Access, PUNICODE_STRING FilePath)
	{
		OBJECT_ATTRIBUTES objectAttributes;
		IO_STATUS_BLOCK ioStatusBlock;
		UNICODE_STRING uszFilePath;
		NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
		ULONG shareFlags = 0;
		ULONG createDisposition = 0;

		if (m_prvFileHandle)
		{
			return STATUS_SUCCESS;
		}

		if (FilePath)
		{
			ntStatus = CovertFilePathToSymbolLinkPath(FilePath);
			if (!NT_SUCCESS(ntStatus))
			{
				return ntStatus;
			}
		}

		InitializeObjectAttributes(&objectAttributes, &m_prvFileSymbolLink, OBJ_CASE_INSENSITIVE, NULL, NULL);
		if (Access & GENERIC_READ)
			shareFlags |= FILE_SHARE_READ;
		if (Access & GENERIC_WRITE)
			shareFlags |= FILE_SHARE_WRITE;
		if (Access & DELETE)
			shareFlags |= FILE_SHARE_DELETE;

		if (Mode == CREATE_ALWAYS)
			createDisposition = FILE_CREATED;
		else if (Mode == OPEN_EXIST)
			createDisposition = FILE_OPEN;
		else if (Mode == OPEN_IF)
			createDisposition = FILE_OPEN_IF;

		ntStatus = ZwCreateFile(
			&m_prvFileHandle,
			Access,
			&objectAttributes,
			&ioStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			shareFlags,
			createDisposition,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);

		if (NT_SUCCESS(ntStatus))
		{
			ntStatus = GetFileStandardInfo();
		}

		return ntStatus;
	}

	NTSTATUS DrvKit_FileMgmt::Read(
		_Inout_ PUCHAR Buffer,
		_In_ ULONG Length,
		_Inout_ PLARGE_INTEGER Offset)
	{
		IO_STATUS_BLOCK ioStatusBlock;
		HANDLE hEvent;
		PKEVENT pkEvent = NULL;
		UNICODE_STRING uszEventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\ReadEvent");

		if (m_prvFileHandle == NULL)
		{
			DrvKit_ReportError("The File was not opened!");
			return STATUS_UNSUCCESSFUL;
		}

		pkEvent = IoCreateSynchronizationEvent(&uszEventName, &hEvent);
		if (pkEvent == NULL)
			return STATUS_UNSUCCESSFUL;

		NTSTATUS ntStatus = ZwReadFile(m_prvFileHandle, hEvent, NULL, NULL, &ioStatusBlock, Buffer, Length, Offset, NULL);
		if (ntStatus == STATUS_PENDING)
		{
			KeWaitForSingleObject(pkEvent, Executive, KernelMode, FALSE, NULL);
			ntStatus = ioStatusBlock.Status;
		}

		ZwClose(hEvent);
		return ntStatus;
	}

	NTSTATUS DrvKit_FileMgmt::Write(
		_Inout_ PUCHAR Buffer,
		_In_ ULONG Length,
		_Inout_ PLARGE_INTEGER Offset)
	{
		if (m_prvFileHandle == NULL)
		{
			DrvKit_ReportError("The File was not opened!");
			return STATUS_UNSUCCESSFUL;
		}

		IO_STATUS_BLOCK ioStatusBlock;

		return ZwWriteFile(m_prvFileHandle, NULL, NULL, NULL, &ioStatusBlock, (PVOID)Buffer, Length, Offset, NULL);
	}

	NTSTATUS DrvKit_FileMgmt::GetFileStandardInfo()
	{
		if (m_prvFileHandle == NULL)
		{
			DrvKit_ReportError("The File was not opened!");
			return STATUS_UNSUCCESSFUL;
		}

		IO_STATUS_BLOCK ioStatusBlock;
		return ZwQueryInformationFile(
			m_prvFileHandle,
			&ioStatusBlock,
			&m_prvFileInfo,
			sizeof(m_prvFileInfo),
			FileStandardInformation);
	}

	NTSTATUS DrvKit_FileMgmt::GetObject(_Inout_ PFILE_OBJECT* FileObj)
	{
		NTSTATUS ntStatus;
		PFILE_OBJECT pFileObj = NULL;

		if (FileObj == NULL)
		{
			return STATUS_INVALID_PARAMETER;
		}

		if (m_prvFileHandle == NULL)
		{
			DrvKit_ReportError("The File was not opened!");
			return STATUS_UNSUCCESSFUL;
		}

		ntStatus = ObReferenceObjectByHandle(m_prvFileHandle, GENERIC_READ, *IoFileObjectType, KernelMode, (PVOID*)&pFileObj, NULL);
		if (NT_SUCCESS(ntStatus))
		{
			*FileObj = pFileObj;
		}

		return ntStatus;
	}

	PVOID DrvKit_FileMgmt::GetMappedBaseAddress()
	{
		PVOID pSegmentBaseAddress = NULL;
		PFILE_OBJECT pFileObj = NULL;
		PCONTROL_AREA pCtlArea = NULL;
		NTSTATUS ntStatus = GetObject(&pFileObj);
		if (!NT_SUCCESS(ntStatus))
			goto cleanup;

		if (!MmIsAddressValid(pFileObj->SectionObjectPointer))
			goto cleanup;

		pCtlArea = (PCONTROL_AREA)pFileObj->SectionObjectPointer->ImageSectionObject;
		if (!MmIsAddressValid(pCtlArea) || !MmIsAddressValid(pCtlArea->Segment))
			goto cleanup;

		pSegmentBaseAddress = pCtlArea->Segment->BasedAddress;

	cleanup:
		if (pFileObj)
			ObDereferenceObject(pFileObj);

		return pSegmentBaseAddress;
	}

	LARGE_INTEGER DrvKit_FileMgmt::GetAllocateSize()
	{
		return m_prvFileInfo.AllocationSize;
	}

	LARGE_INTEGER DrvKit_FileMgmt::GetEndOfFile()
	{
		return m_prvFileInfo.EndOfFile;
	}

	BOOLEAN DrvKit_FileMgmt::IsOpen()
	{
		return m_prvFileHandle != NULL;
	}

	HANDLE DrvKit_FileMgmt::GetHandle()
	{
		return m_prvFileHandle;
	}
};