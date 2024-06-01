#pragma once
#include "IDrvKitCtl.h"
#include "CCActivator.h"

class CCDrvKitCtl :
    public IDrvKitCtl
{
private:
	CCActivator* m_Activator;
	HANDLE m_DrvHandle;
	HANDLE m_DevHandle;

	bool Open();
	void Close();
public:
	CCDrvKitCtl();
	~CCDrvKitCtl();

	virtual bool Start() override;
	virtual bool Stop() override;
	virtual bool SendCmd(PDK_CMD cmd) override;
};

