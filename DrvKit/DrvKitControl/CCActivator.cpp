#include "pch.h"
#include "CCActivator.h"
#include "global.h"

CCActivator::CCActivator():
	_handle_scm(nullptr),
	_desired_access(SERVICE_ALL_ACCESS),
	_service_type(SERVICE_KERNEL_DRIVER),
	_start_type(SERVICE_DEMAND_START),
	_erroe_control(SERVICE_ERROR_NORMAL)

{}

CCActivator::~CCActivator() 
{
	CloseServiceHandle(_handle_scm);
}

bool CCActivator::Init()
{
	bool ret = true;
	_handle_scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (_handle_scm == nullptr)
	{
		DrvKit_ReportError(L"Failed to open SCM.\n");
		ret = false;
	}

	return ret;
}

void CCActivator::SetDesiredAccess(std::uint32_t desired_access)
{
	_desired_access = desired_access;
}

void CCActivator::SetServiceType(std::uint32_t service_type)
{
	_service_type = service_type;
}

void CCActivator::SetStartType(std::uint32_t start_type)
{
	_start_type = start_type;
}

void CCActivator::SetErrorControl(std::uint32_t erroe_control)
{
	_erroe_control = erroe_control;
}

bool CCActivator::Install(std::wstring drvname, std::wstring drvpath)
{
	_drvname = drvname;
	const sch_unique_ptr sch(
		CreateServiceW(
		_handle_scm,          
		drvname.c_str(),
		drvname.c_str(),
		_desired_access,
		_service_type,
		_start_type,
		_erroe_control,
		drvpath.c_str(),
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	));


	if (sch.get() == nullptr)
	{
		auto error = GetLastError();
		if (error == ERROR_SERVICE_EXISTS) return true;

		if (error == ERROR_SERVICE_MARKED_FOR_DELETE)
		{
			DrvKit_ReportError(L"Previous instance of the service is not fully deleted. Try again...\n");
			return false;
		}

		DrvKit_ReportError(L"Failed to create service name: %ws, path:%ws Code = %I32X\n",drvname.c_str() , drvpath.c_str(), error);
		return false;
	}

	return true;
}

bool CCActivator::Remove()
{
	if (Stop())
	{
		sch_unique_ptr sch(OpenServiceW(_handle_scm, _drvname.c_str(), SERVICE_ALL_ACCESS));
		if (sch.get() == nullptr)
		{
			DrvKit_ReportError(L"Failed to open service. Code = %I32X\n", GetLastError());
			return false;
		}

		if (!DeleteService(sch.get()))
		{
			DrvKit_ReportError(L"Failed to delete service. Code = %I32X\n", GetLastError());
			return false;
		}
		
		return true;
	}

	return false;
}

bool CCActivator::Start()
{
	bool ret;
	DWORD dwError;

	sch_unique_ptr sch(OpenServiceW(_handle_scm, _drvname.c_str(), SERVICE_ALL_ACCESS));

	if (sch.get() == nullptr) return false;

	ret = StartServiceW(sch.get(), 0, nullptr);
	if (!ret)
	{
		dwError = GetLastError();
		if (dwError == ERROR_SERVICE_ALREADY_RUNNING) return true;

		DrvKit_ReportError(L"Failed to Start service. Code = %I32X\n", dwError);

		return false;
	}

	return true;
}

bool CCActivator::Stop()
{
	SERVICE_STATUS status;
	bool ret = false;
	sch_unique_ptr sch(OpenServiceW(_handle_scm, _drvname.c_str(), SERVICE_ALL_ACCESS));

	if (sch.get() == nullptr)
	{
		DrvKit_ReportError(L"Failed to open service. Code = %I32X\n", GetLastError());
		goto end;
	}

	ControlService(sch.get(), SERVICE_CONTROL_STOP, &status);
	if (GetLastError() != 0 && GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
	{
		DrvKit_ReportError(L"Failed to Stop service. Code = %I32X\n", GetLastError());
		goto end;
	}

	ret = true;

end:
	return ret;
}