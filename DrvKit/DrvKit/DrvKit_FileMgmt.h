#pragma once
#include "prefix.h"

namespace DK
{
	typedef enum _OPEN_MODE
	{
		OPEN_EXIST = 0,					// 打开已存在的文件，不存在则返回失败
		OPEN_IF,						// 打开已存在的文件，不存在则新建
		CREATE_ALWAYS					// 总是新建，如果有存在的文件将被覆盖
	}OPEN_MODE;

	//0x4 bytes (sizeof)
	typedef struct _SEGMENT_FLAGS
	{
		ULONG TotalNumberOfPtes4132 : 10;                                         //0x0
		ULONG ExtraSharedWowSubsections : 1;                                      //0x0
		ULONG LargePages : 1;                                                     //0x0
		ULONG WatchProto : 1;                                                     //0x0
		ULONG DebugSymbolsLoaded : 1;                                             //0x0
		ULONG WriteCombined : 1;                                                  //0x0
		ULONG NoCache : 1;                                                        //0x0
		ULONG FloppyMedia : 1;                                                    //0x0
		ULONG DefaultProtectionMask : 5;                                          //0x0
		ULONG Binary32 : 1;                                                       //0x0
		ULONG ContainsDebug : 1;                                                  //0x0
		ULONG Spare : 8;                                                          //0x0
	}SEGMENT_FLAGS;

	// 7600 ~ 22631
	typedef struct _SEGMENT
	{
		struct _CONTROL_AREA* ControlArea;										  //0x0
		ULONG TotalNumberOfPtes;												  //0x8
		SEGMENT_FLAGS SegmentFlags;												  //0xc
		ULONG_PTR NumberOfCommittedPages;										  //0x10
		ULONGLONG SizeOfSegment;												  //0x18
		union
		{
			struct _MMEXTEND_INFO* ExtendInfo;									  //0x20
			PVOID BasedAddress;													  //0x20
		};
		EX_PUSH_LOCK SegmentLock;												  //0x28
	} SEGMENT, * PSEGMENT;

	// 7600 ~ 22631
	typedef struct _CONTROL_AREA
	{
		SEGMENT* Segment;
		LIST_ENTRY DereferenceList;
		ULONG_PTR NumberOfSectionReferences;
		ULONG_PTR NumberOfPfnReferences;
		ULONG_PTR NumberOfMappedViews;
		ULONG_PTR NumberOfUserReferences;
		// ... 有改变
	}CONTROL_AREA, * PCONTROL_AREA;
	
	class DrvKit_FileMgmt
	{
	private:
		WCHAR m_Buffer[0x120];
		UNICODE_STRING m_prvFileSymbolLink;
		HANDLE m_prvFileHandle;
		FILE_STANDARD_INFORMATION m_prvFileInfo;

	private:
		NTSTATUS CovertFilePathToSymbolLinkPath(
			_In_ PUNICODE_STRING FilePath);
		NTSTATUS GetFileStandardInfo();
	public:
		DrvKit_FileMgmt();
		DrvKit_FileMgmt(UNICODE_STRING FilePath);
		~DrvKit_FileMgmt();

		NTSTATUS Open(OPEN_MODE Mode, ACCESS_MASK Access, PUNICODE_STRING FilePath = NULL);
		NTSTATUS Read(
			_Inout_ PUCHAR Buffer,
			_In_ ULONG Length,
			_Inout_ PLARGE_INTEGER Offset);
		NTSTATUS Write(
			_Inout_ PUCHAR Buffer,
			_In_ ULONG Length,
			_Inout_ PLARGE_INTEGER Offset);
		NTSTATUS GetObject(_Inout_ PFILE_OBJECT* FileObj);
		PVOID GetMappedBaseAddress();
		LARGE_INTEGER GetAllocateSize();
		LARGE_INTEGER GetEndOfFile();
		BOOLEAN IsOpen();
		HANDLE GetHandle();
	};

};