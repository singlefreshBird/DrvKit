#pragma once
#include <IDrvKitCtl.h>
#include <DrvKit_Public.h>

class CCDrvKit_Mgmt
{
private:
	IDrvKitCtl* _DrvKitCtl;

public:
	CCDrvKit_Mgmt();
	~CCDrvKit_Mgmt();

	bool Init();
	bool Start();
	bool Stop();
	bool SendCmd(PDK_CMD Cmd);
};

