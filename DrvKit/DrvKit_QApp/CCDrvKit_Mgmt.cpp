#include "CCDrvKit_Mgmt.h"

#pragma comment(lib,"DrvKitControl.lib")

CCDrvKit_Mgmt::CCDrvKit_Mgmt():
	_DrvKitCtl(nullptr)
{}

CCDrvKit_Mgmt::~CCDrvKit_Mgmt()
{

	if (_DrvKitCtl) delete _DrvKitCtl;
}

bool CCDrvKit_Mgmt::Init()
{
	if (_DrvKitCtl) return true;

	_DrvKitCtl = GetDrvKitObject();

	return _DrvKitCtl != nullptr;
}

bool CCDrvKit_Mgmt::Start()
{
	return _DrvKitCtl->Start();
}

bool CCDrvKit_Mgmt::Stop()
{
	return _DrvKitCtl->Stop();
}

bool CCDrvKit_Mgmt::SendCmd(PDK_CMD Cmd)
{
	return _DrvKitCtl->SendCmd(Cmd);
}