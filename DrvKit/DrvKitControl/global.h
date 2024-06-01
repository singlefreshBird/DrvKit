#pragma once
#include <atlstr.h>
#define MAX_SIZE 0x200

#define DrvKit_ReportError(format,...)do{ \
    DebugPrintW(L"[-] %ws:%d:%ws() "\
		format\
		,__FILE__,__LINE__,__FUNCTION__,##__VA_ARGS__);\
}while(0)

static void DebugPrintW(const wchar_t* format, ...)
{
	CStringW csErr;
	va_list args;
	va_start(args, format);
	csErr.FormatV(format, args);
	va_end(args);

	OutputDebugStringW(csErr.GetBuffer());
}