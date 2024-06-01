#pragma once
#include "IDrvKit_Enumerator.h"
#include <QString>
#include <vector>

class CCDrvKit_ProcessEnumerator : public IDrvKit_Enumerator
{
public:
	bool Enumerate(void* Param, uint32_t ProcessId = 0);
};

class CCProcess
{
public:
	CCProcess(ULONG ProcessId, QString ProcessName);
	~CCProcess();

	const QString& GetName()const;
	const ULONG GetProcessId()const;
	const QString GetFullPath()const;
	HICON GetIcon()const;

protected:
	ULONG m_ProcessId;
	QString m_ProcessName;
};

using process_collection_unique_ptr = std::unique_ptr<std::vector<CCProcess>>;
using process_collection_ptr = std::vector<CCProcess>*;