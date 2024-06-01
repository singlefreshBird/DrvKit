#pragma once
#include <DrvKit_Public.h>

class IDrvKitCtl
{
public:
	virtual bool Start() = 0;
	virtual bool Stop() = 0;
	virtual bool SendCmd(PDK_CMD cmd) = 0;
};

extern"C" __declspec(dllexport) IDrvKitCtl * _stdcall GetDrvKitObject();