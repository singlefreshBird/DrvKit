#pragma once

#include <QtWidgets/QWidget>
#include <QStringListModel>
#include "ui_CCDrvKit_App.h"
#include "CCDrvKit_Mgmt.h"

class CCDrvKit_App : public QWidget
{
    Q_OBJECT

public:
    CCDrvKit_App(QWidget *parent = nullptr);
    ~CCDrvKit_App();

    void EnumProcessList();
    void EnumModuleList(uint32_t Pid);
protected:
    bool PriviligeEscalation();
private slots:
    void ComboBox_ProcList_Activated(int);
    void ComboBox_ProcList_Activated(QString);
    void ComboBox_ProcList_Highlighted(QString);
    void PushButton_ChoiceProcFullPath_Clicked();
    void PushButton_AddModule_Clicked();
    void PushButton_RemoveModule_Clicked();
    void PushButton_ClearModule_Clicked();
    void PushButton_Existing_LoadModule_Clicked();
    void PushButton_Existing_UnloadModule_Clicked();
    void CheckBox_Creating_LoadModule_Clicked(bool);
    void ListView_WaitingLoad_DropEvet(QDropEvent*);

private:
    CCDrvKit_Mgmt* m_DrvKitManager;
    QStringListModel* m_CreatingLoadedListMode;
    Ui::CCDrvKit_AppClass ui;
};
