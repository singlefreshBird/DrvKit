#pragma once
#include <windows.h>
#include <memory>

class IDrvKit_Enumerator
{
public:
	virtual bool Enumerate(void* Param, uint32_t ProcessId = 0) = 0;
	virtual ~IDrvKit_Enumerator() {}
};

template <class _Ty>
class deleter
{
public:
	using pointer = HANDLE;
	void operator()(_Ty p) const
	{
		if (p != nullptr) CloseHandle(p);
	}
};

using unique_handle = std::unique_ptr<HANDLE, deleter<HANDLE>>;