#pragma once
#include "prefix.h"
#include "DrvKit_FileMgmt.h"
#include<ntimage.h>

namespace DK
{
	class DrvKit_BinaryAnalyze
	{
	private:
		PUCHAR m_prvImageLoadBase;
		SIZE_T m_ImageSize;
		MODE m_prvAccessMode;
		BOOLEAN m_prvIsX64;
		BOOLEAN m_prvIsNeedFixOffset;
		ULONG64 m_prvCheckSum;
		BOOLEAN m_prvIsNeedClear;
		PFILE_OBJECT m_prvFileObject;

	private:
		PVOID GetImageNtHeader();

	public:
		DrvKit_BinaryAnalyze(MODE AccessMode);
		~DrvKit_BinaryAnalyze();
		PIMAGE_SECTION_HEADER GetImageSectionHeader(PULONG NumOfSections);
		PIMAGE_SECTION_HEADER GetSectionHeaderFromVirtualAddress(ULONG VirtualAddress);
		BOOLEAN LoadFromFile(UNICODE_STRING FilePath);
		BOOLEAN LoadFromMap(PUCHAR BaseAddress);
		ULONG64 CalcCheckSum();
		BOOLEAN Validate();
		ULONG FoaToRva(ULONG Foa);
		ULONG RvaToFoa(ULONG Rva);
		PVOID GetEntryPointer();
		PVOID GetSectionDataEntry(PCHAR SectionName);
		PVOID GetFunAddressFromEAT(PCHAR Name);
		PVOID GetImageDataDirectoryEntry(ULONG Index);
		BOOLEAN IsX64()const;
		PUCHAR GetImageLoadBase()const;
		SIZE_T GetImageSize()const;
		PUCHAR GetMappingAddress();
		MODE GetAccessMode()const;
		ULONG64 GetCheckSum()const;
	};
};