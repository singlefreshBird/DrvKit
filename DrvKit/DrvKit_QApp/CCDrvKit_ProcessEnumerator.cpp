#include "CCDrvKit_ProcessEnumerator.h"
#include <qlogging.h>
#include <QString>
#include <TlHelp32.h>
#include <Psapi.h>

bool CCDrvKit_ProcessEnumerator::Enumerate(void* Param, uint32_t ProcessId)
{
	bool bNext;
	PROCESSENTRY32W procEnt;

	procEnt.dwSize = sizeof(PROCESSENTRY32W);
	
	if (Param == nullptr) return false;

	process_collection_ptr pProc_cell = (process_collection_ptr)Param;

	unique_handle hSnap(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));

	
	if (hSnap.get() == nullptr) return false;

	bNext = ::Process32FirstW(hSnap.get(), &procEnt);
	while (bNext)
	{
		CCProcess Process{ procEnt.th32ProcessID, QString::fromStdWString(procEnt.szExeFile) };
		pProc_cell->emplace(pProc_cell->end(), Process);
		bNext = ::Process32NextW(hSnap.get(), &procEnt);
	}


	return true;
}

CCProcess::CCProcess(ULONG ProcessId, QString ProcessName):
	m_ProcessId(ProcessId),
	m_ProcessName(ProcessName)
{}

CCProcess::~CCProcess()
{}

const QString& CCProcess::GetName() const
{
	return m_ProcessName;
}

const ULONG CCProcess::GetProcessId()const
{
	return m_ProcessId;
}

const QString CCProcess::GetFullPath() const
{
	unique_handle hProc(OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_ProcessId));
	if (hProc.get() == nullptr) return "";

	wchar_t wzPath[MAX_PATH] = { 0 };
	DWORD dwRet = ::GetModuleFileNameExW(hProc.get(),nullptr, wzPath, MAX_PATH);
	QString fullPath = QString::fromStdWString(wzPath);

	return dwRet == 0 ? "" : fullPath;
}

HICON CCProcess::GetIcon()const
{
	HICON hIcon;
	SHFILEINFO fileInfo;
	DWORD_PTR dwRet = 0;

	dwRet = ::SHGetFileInfoW(GetFullPath().toStdWString().c_str(), 0, &fileInfo, sizeof(fileInfo), SHGFI_ICON);
	
	return dwRet == NULL ? nullptr : fileInfo.hIcon;
}
