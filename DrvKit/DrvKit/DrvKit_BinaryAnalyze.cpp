#include "DrvKit_BinaryAnalyze.h"

namespace DK
{

	DrvKit_BinaryAnalyze::DrvKit_BinaryAnalyze(MODE AccessMode):
		m_prvImageLoadBase(NULL),
		m_ImageSize(0),
		m_prvAccessMode(AccessMode),
		m_prvIsX64(FALSE),
		m_prvIsNeedFixOffset(TRUE),
		m_prvCheckSum(0),
		m_prvIsNeedClear(FALSE),
		m_prvFileObject(NULL)
	{
		
	}

	DrvKit_BinaryAnalyze::~DrvKit_BinaryAnalyze()
	{
		if (m_prvIsNeedClear)
		{
			delete[] m_prvImageLoadBase;
		}

		if (m_prvFileObject)
		{
			ObDereferenceObject(m_prvFileObject);
		}
	}

	PIMAGE_SECTION_HEADER DrvKit_BinaryAnalyze::GetImageSectionHeader(PULONG NumOfSections)
	{
		if (NumOfSections == NULL)
			return NULL;

		PIMAGE_SECTION_HEADER pSecHdr = NULL;
		BOOLEAN bX64;
		PVOID pImgNtHdr = NULL;


		__try
		{
			do
			{
				pImgNtHdr = this->GetImageNtHeader();

				pSecHdr = IMAGE_FIRST_SECTION((PIMAGE_NT_HEADERS)pImgNtHdr);
#ifdef _WIN64
				if (!this->IsX64())
				{
					if (m_prvAccessMode == UserMode)
						ProbeForRead(pImgNtHdr, sizeof(IMAGE_NT_HEADERS32), 1);
					else if (!MmIsAddressValid(pImgNtHdr) || !MmIsAddressValid((PCHAR)pImgNtHdr + sizeof(IMAGE_NT_HEADERS32)))
						break;

					*NumOfSections = ((PIMAGE_NT_HEADERS32)pImgNtHdr)->FileHeader.NumberOfSections;
					break;
				}

#endif
				if (m_prvAccessMode == UserMode)
					ProbeForRead(pImgNtHdr, sizeof(IMAGE_NT_HEADERS64), 1);
				else if (!MmIsAddressValid(pImgNtHdr) || !MmIsAddressValid((PCHAR)pImgNtHdr + sizeof(IMAGE_NT_HEADERS64)))
					break;
				*NumOfSections = ((PIMAGE_NT_HEADERS64)pImgNtHdr)->FileHeader.NumberOfSections;
			} while (FALSE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DrvKit_ReportException("An exception occurred during parsing PE.\n");
		}

		return pSecHdr;
	}

	PVOID DrvKit_BinaryAnalyze::GetImageNtHeader()
	{
		PVOID pImgNtHdr = NULL;

		__try
		{
			do
			{
				PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)this->GetImageLoadBase();

				if (pDosHdr == NULL)
				{
					break;
				}

				if (m_prvAccessMode == UserMode)
					ProbeForRead(pDosHdr, sizeof(IMAGE_DOS_HEADER), 1);
				else if (!MmIsAddressValid(pDosHdr) || !MmIsAddressValid((PCHAR)pDosHdr + sizeof(IMAGE_DOS_HEADER)))
					break;

				pImgNtHdr = this->GetImageLoadBase() + pDosHdr->e_lfanew;

			} while (FALSE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DrvKit_ReportException("An exception occurred during getting NT header!\n");
		}

		return pImgNtHdr;
	}

	PIMAGE_SECTION_HEADER DrvKit_BinaryAnalyze::GetSectionHeaderFromVirtualAddress(ULONG VirtualAddress)
	{
		ULONG ulSectionNum = 0;
		PIMAGE_SECTION_HEADER pSenHdr = GetImageSectionHeader(&ulSectionNum);
		if (pSenHdr == NULL)
		{
			return NULL;
		}

		for (ULONG i = 0; i < ulSectionNum; i++)
		{
			if (VirtualAddress >= pSenHdr[i].VirtualAddress &&
				VirtualAddress < pSenHdr[i].SizeOfRawData + pSenHdr[i].VirtualAddress)
			{
				return &pSenHdr[i];
			}
		}

		return NULL;
	}

	BOOLEAN DrvKit_BinaryAnalyze::IsX64()const
	{
		return m_prvIsX64;
	}

	BOOLEAN DrvKit_BinaryAnalyze::LoadFromFile(UNICODE_STRING FilePath)
	{
		DrvKit_FileMgmt fileMgmt(FilePath);
		NTSTATUS ntStatus =  fileMgmt.Open(OPEN_EXIST, GENERIC_READ);
		BOOLEAN bRet = FALSE;
		LARGE_INTEGER liOffset = { 0 };

		if (!NT_SUCCESS(ntStatus))
		{
			goto end;
		}

		ntStatus = fileMgmt.GetObject(&m_prvFileObject);
		if (!NT_SUCCESS(ntStatus))
		{
			goto end;
		}

		ULONG ulBinSize = fileMgmt.GetEndOfFile().LowPart;
		if (ulBinSize > 0x400 * 0x400 * 300)
		{
			DrvKit_ReportError("Can't load size of PE file large than 300M.\n");
			goto end;
		}

		m_prvImageLoadBase = new UCHAR[ulBinSize];
		if (m_prvImageLoadBase == NULL)
		{
			DrvKit_ReportError("Failed alloc memory.\n");
			goto end;
		}

		ntStatus = fileMgmt.Read(m_prvImageLoadBase, ulBinSize, &liOffset);
		if (!NT_SUCCESS(ntStatus))
		{
			goto end;
		}

		if (!Validate())
		{
			delete[] m_prvImageLoadBase;
			m_prvImageLoadBase = NULL;
			goto end;
		}

		m_prvIsNeedClear = TRUE;
		bRet = TRUE;
	end:
		return bRet;
	}

	BOOLEAN DrvKit_BinaryAnalyze::LoadFromMap(PUCHAR BaseAddress)
	{
		BOOLEAN bRet = FALSE;

		if (BaseAddress == NULL)
			return FALSE;

		m_prvImageLoadBase = BaseAddress;
		bRet = Validate();
		if (!bRet)
		{
			m_prvImageLoadBase = NULL;
			goto end;
		}

		m_prvIsNeedFixOffset = FALSE;

	end:
		return bRet;
	}

	ULONG64 DrvKit_BinaryAnalyze::CalcCheckSum()
	/*
	 * 实际校验和并不是这么算的，后续找时间再修改吧
	 */
	{
		ULONG64 CheckSum = 0;

		__try
		{
			do
			{
				PVOID pImgNtHdr = this->GetImageNtHeader();
				if (!this->IsX64())
				{
					if (this->GetAccessMode() == UserMode)
						ProbeForRead(pImgNtHdr, sizeof(IMAGE_NT_HEADERS64), 1);
					else if (!MmIsAddressValid(pImgNtHdr) || !MmIsAddressValid((PCHAR)pImgNtHdr + sizeof(IMAGE_NT_HEADERS64)))
						break;

					CheckSum = ((ULONG64)(((PIMAGE_NT_HEADERS64)pImgNtHdr)->FileHeader.TimeDateStamp) << 32) |
						((PIMAGE_NT_HEADERS64)pImgNtHdr)->OptionalHeader.SizeOfImage;
				}
				else
				{
					if (this->GetAccessMode() == UserMode)
						ProbeForRead(pImgNtHdr, sizeof(IMAGE_NT_HEADERS32), 1);
					else if (!MmIsAddressValid(pImgNtHdr) || !MmIsAddressValid((PCHAR)pImgNtHdr + sizeof(IMAGE_NT_HEADERS32)))
						break;

					CheckSum = ((ULONG64)(((PIMAGE_NT_HEADERS32)pImgNtHdr)->FileHeader.TimeDateStamp) << 32) |
						((PIMAGE_NT_HEADERS32)pImgNtHdr)->OptionalHeader.SizeOfImage;
				}
			} while (FALSE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DrvKit_ReportException("An exception occurred during calculating checksum!\n");
		}

		return CheckSum;
	}

	BOOLEAN DrvKit_BinaryAnalyze::Validate()
	{
		BOOLEAN bRet = FALSE;

		__try
		{
			do
			{
				PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)this->GetImageLoadBase();
				if (this->GetAccessMode() == UserMode)
					ProbeForRead(pDosHdr, sizeof(IMAGE_DOS_HEADER), 1);
				else if (!MmIsAddressValid(pDosHdr) || !MmIsAddressValid((PCHAR)pDosHdr + sizeof(IMAGE_DOS_HEADER)))
					break;

				if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
					break;

				PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(this->GetImageLoadBase() + pDosHdr->e_lfanew);

				if (m_prvAccessMode == UserMode)
					ProbeForRead(pNtHdr, sizeof(IMAGE_NT_HEADERS), 1);
				else if (!MmIsAddressValid(pNtHdr) || !MmIsAddressValid((PCHAR)pNtHdr + sizeof(IMAGE_NT_HEADERS)))
					break;

				if (pNtHdr->Signature != IMAGE_NT_SIGNATURE)
					break;

				if (pNtHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
					m_prvIsX64 = TRUE;

				if (IsX64())
				{
					if (((PIMAGE_NT_HEADERS64)pNtHdr)->OptionalHeader.CheckSum)
					{
						m_prvCheckSum = ((PIMAGE_NT_HEADERS64)pNtHdr)->OptionalHeader.CheckSum;
						m_ImageSize = ((PIMAGE_NT_HEADERS64)pNtHdr)->OptionalHeader.SizeOfImage;
					}
				}
				else
				{
					if (((PIMAGE_NT_HEADERS32)pNtHdr)->OptionalHeader.CheckSum)
					{
						m_prvCheckSum = ((PIMAGE_NT_HEADERS32)pNtHdr)->OptionalHeader.CheckSum;
						m_ImageSize = ((PIMAGE_NT_HEADERS32)pNtHdr)->OptionalHeader.SizeOfImage;
					}
				}

				if (m_prvCheckSum == 0)
					m_prvCheckSum = CalcCheckSum();

				bRet = TRUE;
			} while (FALSE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DrvKit_ReportException("An exception occurred during validating PE!\n");
		}

		if (!bRet)
			DrvKit_ReportError("This isn't a valid PE.\n");

		return bRet;
	}

	ULONG DrvKit_BinaryAnalyze::FoaToRva(ULONG Foa)
	{
		if (Foa < sizeof(IMAGE_DOS_HEADER))
			return Foa;

		ULONG Rva = Foa;

		__try
		{
			do
			{
				ULONG nSec;
				PIMAGE_SECTION_HEADER pImgSecHdr = GetImageSectionHeader(&nSec);

				if (m_prvAccessMode == UserMode)
					ProbeForRead(pImgSecHdr, sizeof(IMAGE_SECTION_HEADER), 1);
				else if (!MmIsAddressValid(pImgSecHdr) || !MmIsAddressValid((PCHAR)pImgSecHdr + sizeof(IMAGE_SECTION_HEADER)))
					break;

				for (ULONG i = 0; i < nSec; i++)
				{
					if (Foa >= pImgSecHdr[i].PointerToRawData &&
						Foa < (pImgSecHdr[i].PointerToRawData + pImgSecHdr[i].SizeOfRawData))
					{
						Rva = Foa - pImgSecHdr[i].PointerToRawData + pImgSecHdr[i].VirtualAddress;
						break;
					}
				}
			} while (FALSE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DrvKit_ReportException("An exception occurred during Foa to Rva!\n");
		}

		return Rva;
	}

	ULONG DrvKit_BinaryAnalyze::RvaToFoa(ULONG Rva)
	{
		if (!m_prvIsNeedFixOffset || Rva < sizeof(IMAGE_DOS_HEADER))
			return Rva;

		ULONG Foa = Rva;
		ULONG nSec;

		__try
		{
			do
			{
				ULONG nSec;
				PIMAGE_SECTION_HEADER pImgSecHdr = GetImageSectionHeader(&nSec);

				if (m_prvAccessMode == UserMode)
					ProbeForRead(pImgSecHdr, sizeof(IMAGE_SECTION_HEADER), 1);
				else if (!MmIsAddressValid(pImgSecHdr) || !MmIsAddressValid((PCHAR)pImgSecHdr + sizeof(IMAGE_SECTION_HEADER)))
					break;

				for (ULONG i = 0; i < nSec; i++)
				{
					if (Rva >= pImgSecHdr[i].VirtualAddress &&
						Rva < (pImgSecHdr[i].VirtualAddress + pImgSecHdr[i].Misc.VirtualSize))
					{
						Foa = Rva - pImgSecHdr[i].VirtualAddress + pImgSecHdr[i].PointerToRawData;
						break;
					}
				}

			} while (FALSE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DrvKit_ReportException("An exception occurred during Rva to Foa!\n");
		}

		return Foa;
	}

	PVOID DrvKit_BinaryAnalyze::GetEntryPointer()
	{
		if (IsX64())
		{
			PIMAGE_NT_HEADERS64 pNtHdr64 = (PIMAGE_NT_HEADERS64)GetImageNtHeader();
			if (pNtHdr64)
			{
				return GetImageLoadBase() + RvaToFoa(pNtHdr64->OptionalHeader.AddressOfEntryPoint);
			}

		}
		else
		{
			PIMAGE_NT_HEADERS32 pNtHdr32 = (PIMAGE_NT_HEADERS32)GetImageNtHeader();
			if (pNtHdr32)
			{
				return GetImageLoadBase() + RvaToFoa(pNtHdr32->OptionalHeader.AddressOfEntryPoint);
			}
		}

		return NULL;
	}

	PVOID DrvKit_BinaryAnalyze::GetSectionDataEntry(PCHAR SectionName)
	{
		ULONG ulNumOfSections;
		PIMAGE_SECTION_HEADER pSecHdr = GetImageSectionHeader(&ulNumOfSections);
		if (pSecHdr == NULL)
			return NULL;

		for (ULONG i = 0; i < ulNumOfSections; i++)
		{
			if (!_stricmp((char*)pSecHdr[i].Name, SectionName))
			{
				return this->GetImageLoadBase() + this->RvaToFoa(pSecHdr[i].VirtualAddress);
			}
		}

		return NULL;
	}

	PVOID DrvKit_BinaryAnalyze::GetFunAddressFromEAT(PCHAR Name)
	{
		if (Name == NULL)
			return NULL;

		PIMAGE_EXPORT_DIRECTORY pImgExpDir = NULL;
		PVOID pfn = NULL;
		PVOID pImgNtHdr;

		__try
		{
			do
			{
				pImgNtHdr = this->GetImageNtHeader();
#ifdef _WIN64
				// 判断一下PE的位数
				if (!this->IsX64())
				{
					if (this->GetAccessMode() == UserMode)
						ProbeForRead(pImgNtHdr, sizeof(IMAGE_NT_HEADERS32), 1);
					else if (!MmIsAddressValid(pImgNtHdr) || !MmIsAddressValid((PCHAR)pImgNtHdr + sizeof(IMAGE_NT_HEADERS32)))
						break;

					if (((PIMAGE_NT_HEADERS32)pImgNtHdr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
					{
						break;
					}

					pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(this->GetImageLoadBase() + this->RvaToFoa(
						((PIMAGE_NT_HEADERS32)pImgNtHdr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

				}
				else
				{
					if (this->GetAccessMode() == UserMode)
						ProbeForRead(pImgNtHdr, sizeof(IMAGE_NT_HEADERS64), 1);
					else if (!MmIsAddressValid(pImgNtHdr) || !MmIsAddressValid((PCHAR)pImgNtHdr + sizeof(IMAGE_NT_HEADERS64)))
						break;

					if (((PIMAGE_NT_HEADERS64)pImgNtHdr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
					{
						break;
					}

					pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(this->GetImageLoadBase() + this->RvaToFoa(
						((PIMAGE_NT_HEADERS64)pImgNtHdr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

				}
#else
				if (((PIMAGE_NT_HEADERS32)pImgNtHdr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
				{
					break;
				}

				pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(this->GetImageLoadBase() + this->RvaToFoa(
					((PIMAGE_NT_HEADERS32)pImgNtHdr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

#endif

				if (this->GetAccessMode() == UserMode)
					ProbeForRead(pImgExpDir, sizeof(IMAGE_EXPORT_DIRECTORY), 1);
				else if (!MmIsAddressValid(pImgExpDir) || !MmIsAddressValid((PCHAR)pImgExpDir + sizeof(IMAGE_EXPORT_DIRECTORY)))
					break;

				PULONG AddressOfNames = (PULONG)(RvaToFoa(pImgExpDir->AddressOfNames) + this->GetImageLoadBase());
				PULONG AddressOfFuns = (PULONG)(RvaToFoa(pImgExpDir->AddressOfFunctions) + this->GetImageLoadBase());
				PUSHORT AddressOfNameOrdinals = (PUSHORT)(RvaToFoa(pImgExpDir->AddressOfNameOrdinals) + this->GetImageLoadBase());
				ULONG NumOfNames = pImgExpDir->NumberOfNames;

				for (ULONG i = 0; i < NumOfNames; i++)
				{
					PCHAR NameCmpare = (PCHAR)(this->GetImageLoadBase() + RvaToFoa(AddressOfNames[i]));

					if (this->GetAccessMode() == UserMode)
						ProbeForRead(NameCmpare, sizeof(PVOID), 1);
					else if (!MmIsAddressValid(NameCmpare))
						break;

					if (!_stricmp(NameCmpare, Name))
					{
						pfn = (PVOID)(RvaToFoa(AddressOfFuns[AddressOfNameOrdinals[i]]) + this->GetImageLoadBase());
						break;
					}
				}

			} while (FALSE);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DrvKit_ReportException("An exception occurred during parsing PE.\n");
		}

		return pfn;
	}

	PVOID DrvKit_BinaryAnalyze::GetImageDataDirectoryEntry(ULONG Index)
	{
		ULONG Size;
		return RtlImageDirectoryEntryToData(this->GetImageLoadBase(), !m_prvIsNeedFixOffset, Index, &Size);
	}
	
	PUCHAR DrvKit_BinaryAnalyze::GetImageLoadBase() const
	{
		return m_prvImageLoadBase;
	}

	SIZE_T DrvKit_BinaryAnalyze::GetImageSize() const
	{
		return m_ImageSize;
	}

	PUCHAR DrvKit_BinaryAnalyze::GetMappingAddress()
	{
		PVOID pSegmentBaseAddress = NULL;
		PCONTROL_AREA pCtlArea = NULL;

		if (m_prvFileObject == NULL)
		{
			return NULL;
		}

		if (!MmIsAddressValid(m_prvFileObject->SectionObjectPointer))
			goto end;

		pCtlArea = (PCONTROL_AREA)m_prvFileObject->SectionObjectPointer->ImageSectionObject;
		if (!MmIsAddressValid(pCtlArea) || !MmIsAddressValid(pCtlArea->Segment))
			goto end;

		pSegmentBaseAddress = pCtlArea->Segment->BasedAddress;

	end:
		return (PUCHAR)pSegmentBaseAddress;
	}
	
	MODE DrvKit_BinaryAnalyze::GetAccessMode()const
	{
		return m_prvAccessMode;
	}

	ULONG64 DrvKit_BinaryAnalyze::GetCheckSum()const
	{
		return m_prvCheckSum;
	}
};