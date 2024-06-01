#pragma once
#include<string>
#include<windows.h>
#include<memory>

class CCActivator 
{
private:
	SC_HANDLE _handle_scm;
	std::wstring _drvname;
	std::uint32_t _desired_access;
	std::uint32_t _service_type;
	std::uint32_t _start_type;
	std::uint32_t _erroe_control;
public:
	CCActivator();
	~CCActivator();

	bool Init();
	void SetDesiredAccess(std::uint32_t desired_access);
	void SetServiceType(std::uint32_t service_type);
	void SetStartType(std::uint32_t start_type);
	void SetErrorControl(std::uint32_t erroe_control);
	bool Install(std::wstring drvname, std::wstring drvpath);
	bool Remove();
	bool Start();
	bool Stop();
};

template<typename T>
class sch_deleter
{
public:
	using pointer = SC_HANDLE;
	void operator()(T p)const
	{
		if (p != nullptr) CloseServiceHandle(p);
	}
};

using sch_unique_ptr = std::unique_ptr<SC_HANDLE, sch_deleter<SC_HANDLE>>;