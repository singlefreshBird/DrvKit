#include "pch.h"
#include "global.h"
#include "CCDrvKitCtl.h"
#include "CCActivator.h"
#include <string>

CCDrvKitCtl::CCDrvKitCtl()
{
	m_Activator = nullptr;
	m_DrvHandle = nullptr;
	
}
CCDrvKitCtl::~CCDrvKitCtl()
{
	if (m_Activator) delete m_Activator;
}


bool CCDrvKitCtl::Start()
{
	bool ret = false;
	
	WCHAR wzDrvName[30] = { 0 };
	CString path;
	SYSTEM_INFO sysInfo;

	try
	{
		GetNativeSystemInfo(&sysInfo);
		if (sysInfo.dwProcessorType == PROCESSOR_INTEL_IA64 || sysInfo.dwProcessorType == PROCESSOR_AMD_X8664)
			wcscpy_s(wzDrvName, 29, L"\\DrvKit_x64.sys");
		else 
			wcscpy_s(wzDrvName, 29, L"\\DrvKit_x32.sys");
		

		if (m_Activator == nullptr)
		{
			m_Activator = new CCActivator();
			ret = m_Activator->Init();
			if (ret == false) goto end;
		}

		if(!GetModuleFileName(NULL, path.GetBufferSetLength(MAX_PATH + 1), MAX_PATH)) goto end;
		path.ReleaseBuffer();
		int pos = path.ReverseFind('\\');
		path = path.Left(pos);
		path.Append(wzDrvName);

		ret = m_Activator->Install(L"DrvKit_Service", path.GetBuffer());
		if (ret == false) goto end;

		ret = m_Activator->Start();
		if (ret == false) goto end;

		ret = Open();
	}
	catch(std::bad_alloc)
	{
		DrvKit_ReportError(L"Failed to Active.\n");
	}
	
end:
	return ret;
}

bool CCDrvKitCtl::Stop()
{
	if (m_Activator == nullptr) return false;

	if (!m_Activator->Stop()) return false;

	Close();
	return m_Activator->Remove();
}

bool CCDrvKitCtl::SendCmd(PDK_CMD cmd)
{
	DWORD dwRetSIze;
	return DeviceIoControl(m_DevHandle, IOCTL_DRVKIT_CONTROL, cmd, sizeof(DK_CMD), NULL, 0, &dwRetSIze, NULL);
}

bool CCDrvKitCtl::Open()
{
	m_DevHandle = CreateFileW(
		USER_SYMBOLIC_LINK_NAME,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		0);

	if ((m_DevHandle == INVALID_HANDLE_VALUE) || m_DevHandle == nullptr)
	{
		DrvKit_ReportError(L"Failed to open driver. Code = %I32X\n", GetLastError());
	}

	return (m_DevHandle != NULL) && (m_DevHandle != INVALID_HANDLE_VALUE);
}

void CCDrvKitCtl::Close()
{
	if (m_DrvHandle != NULL || m_DrvHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_DrvHandle);
		m_DrvHandle = INVALID_HANDLE_VALUE;
	}

	if (m_DevHandle != NULL || m_DevHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_DevHandle);
		m_DevHandle = INVALID_HANDLE_VALUE;
	}
}

extern"C" __declspec(dllexport) IDrvKitCtl* _stdcall GetDrvKitObject()
{
	IDrvKitCtl* obj = nullptr;

	try
	{
		obj = new CCDrvKitCtl;
	}
	catch (std::bad_alloc* e)
	{
		DrvKit_ReportError(L"%s\n",e->what());
	}
	
	return obj;
}