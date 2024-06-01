#include "CCDrvKit_App.h"
#include "IDrvKit_Enumerator.h"
#include "CCDrvKit_ProcessEnumerator.h"
#include "CCDrvKit_ModuleEnumerator.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QDropEvent>
#include <QMimeData>
#include <QFileIconProvider>

CCDrvKit_App::CCDrvKit_App(QWidget *parent)
    : QWidget(parent),
	m_CreatingLoadedListMode(nullptr),
	m_DrvKitManager(nullptr)
{
    ui.setupUi(this);
	setWindowFlags(Qt::WindowMinimizeButtonHint | Qt::WindowCloseButtonHint); // 设置禁止最大化
	setFixedSize(806, 520); // 禁止改变窗口大小。

	if (!PriviligeEscalation())
	{
		QMessageBox::warning(nullptr, u8"警告", u8"获取高权限失败！");
	}

	m_CreatingLoadedListMode = new QStringListModel;
	m_DrvKitManager = new CCDrvKit_Mgmt;
	if (!m_DrvKitManager->Init())
	{
		QMessageBox::critical(nullptr, u8"错误", u8"初始化管理器失败！");
		exit(0);
	}

	if (!m_DrvKitManager->Start())
	{
		QMessageBox::critical(nullptr, u8"错误", u8"初始化服务失败！");
		exit(0);
	}

	ui.listView_WaitingLoadModule->setModel(m_CreatingLoadedListMode);

	// 绘制已加载模块树形框的标题
	QStringList title;
	title << "Name" << "BaseLoadAddress" << "Size" << "Path";
	
	ui.treeWidget_Existing_Loaded_Module->setHeaderLabels(title);

	
	// 注册组件事件
	connect(ui.pushButton_Choice_ProcPath, SIGNAL(clicked()),this, SLOT(PushButton_ChoiceProcFullPath_Clicked()));
	connect(ui.pushButton_Creating_Add_Module, SIGNAL(clicked()), this, SLOT(PushButton_AddModule_Clicked()));
	connect(ui.pushButton_Creating_Remove_Module, SIGNAL(clicked()), this, SLOT(PushButton_RemoveModule_Clicked()));
	connect(ui.pushButton_Creating_Clear_Module, SIGNAL(clicked()), this, SLOT(PushButton_ClearModule_Clicked()));
	connect(ui.pushButton_Existed_Load, SIGNAL(clicked()), this, SLOT(PushButton_Existing_LoadModule_Clicked()));
	connect(ui.checkBox_Creating_LoadModule, SIGNAL(clicked(bool)), this, SLOT(CheckBox_Creating_LoadModule_Clicked(bool)));
	connect(ui.pushButton_Existed_Unload, SIGNAL(clicked()), this, SLOT(PushButton_Existing_UnloadModule_Clicked()));
	connect(ui.ComboBox_ProcList, SIGNAL(activated(int)), this, SLOT(ComboBox_ProcList_Activated(int)));
	connect(ui.ComboBox_ProcList, SIGNAL(activated(QString)), this, SLOT(ComboBox_ProcList_Activated(QString)));
	connect(ui.ComboBox_ProcList, SIGNAL(highlighted(QString)), this, SLOT(ComboBox_ProcList_Highlighted(QString)));
	//connect(ui.listView_WaitingLoadModule, SIGNAL(dropEvent(QDropEvent*)), this, SLOT(ListView_WaitingLoad_DropEvet(QDropEvent*)));
}

CCDrvKit_App::~CCDrvKit_App()
{
	if (m_CreatingLoadedListMode) delete m_CreatingLoadedListMode;
	if (m_DrvKitManager)
	{
		m_DrvKitManager->Stop();
		delete m_DrvKitManager;
	}
}


void CCDrvKit_App::EnumProcessList()
{
	std::unique_ptr<IDrvKit_Enumerator> process_list = std::make_unique<CCDrvKit_ProcessEnumerator>();
	process_collection_unique_ptr proc_set = std::make_unique<std::vector<CCProcess>>();
	QFileIconProvider qIcon;

	if (process_list->Enumerate(proc_set.get()))
	{
		for (auto item = proc_set->begin(); item != proc_set->end(); item++)
		{
			auto icon = qIcon.icon(QFileInfo(item->GetFullPath()));
			ui.ComboBox_ProcList->addItem(icon, item->GetName() + " (" + QString::number(item->GetProcessId()) + ")");
		}
	}
}

void CCDrvKit_App::EnumModuleList(uint32_t Pid)
{
	std::unique_ptr<IDrvKit_Enumerator> module_list = std::make_unique<CCDrvKit_ModuleEnumerator>();
	module_collection_unique_ptr proc_set = std::make_unique<std::vector<CCModule>>();

	if (module_list->Enumerate(proc_set.get(), Pid))
	{
		for (auto item = proc_set->begin(); item != proc_set->end(); item++)
		{
			QStringList text;
			QString hexSize;
			char szhexStr[0x20] = { 0 };

			sprintf_s(szhexStr, "0x%I32x%I32x", (ULONG)(item->GetBaseAddress() >> 0x20), (ULONG)item->GetBaseAddress());

			text << item->GetName() << 
				szhexStr <<
				hexSize.sprintf("%x", item->GetSize()) << 
				item->GetFullPath();

			QTreeWidgetItem* listItem = new QTreeWidgetItem(text);
			listItem->setCheckState(0, Qt::Unchecked);
			ui.treeWidget_Existing_Loaded_Module->addTopLevelItem(listItem);
		}
	}
}

bool CCDrvKit_App::PriviligeEscalation()
{
	HANDLE hToken = NULL;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges = { 0 };
	
	auto bRet = ::OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	if (bRet == false) return false;

	unique_handle h(hToken);

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidValue))
	{
		return false;
	}
	// 设置提升权限信息
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	// 提升进程令牌访问权限
	bRet = ::AdjustTokenPrivileges(h.get(), FALSE, &tokenPrivileges, 0, NULL, NULL);
	if (bRet == false) return false;

	return GetLastError() == ERROR_SUCCESS;
}

void CCDrvKit_App::PushButton_ChoiceProcFullPath_Clicked()
{
	QString fileName = QFileDialog::getOpenFileName(
		this,
		u8"请选择一个可执行程序",
		"C:\\",
		"(*.exe)");

	if (fileName.size())
	{
		fileName.replace("/", "\\");
		ui.textEdit_ProcFullPath->setText(fileName);

		DK_CMD cmd;
		ZeroMemory(&cmd, sizeof(cmd));
		cmd.Opertion = OPERTION::eOption_SetCreatingProcessPath;

		wcsncpy_s(cmd.Cmd.LOAD_CREATING_PROCESS_CMDLINE.ProcessPath, fileName.toStdWString().c_str(), fileName.size());
		OutputDebugStringW(cmd.Cmd.LOAD_CREATING_PROCESS_CMDLINE.ProcessPath);
		m_DrvKitManager->SendCmd(&cmd);
	}
}

void CCDrvKit_App::PushButton_AddModule_Clicked()
{
	QString fileName = QFileDialog::getOpenFileName(
		this,
		u8"请选择一个DLL文件",
		"C:\\",
		"(*.dll)");
	
	if (fileName.size() > 0)
	{
		if (fileName.size() < MAX_PATH_SIZE)
		{
			// 修正一下路径分隔符
			fileName.replace("/", "\\");

			DK_CMD cmd;

			ZeroMemory(&cmd, sizeof(cmd));
			cmd.Opertion = OPERTION::eOption_AddDllItem;
			auto path = fileName.toStdWString();
			wcsncpy_s(cmd.Cmd.ADD_DLL_ITEM.DllPath, path.c_str(), path.size());

			if (m_DrvKitManager->SendCmd(&cmd))
			{
				auto row = m_CreatingLoadedListMode->rowCount();
				m_CreatingLoadedListMode->insertRow(row);
				QModelIndex index = m_CreatingLoadedListMode->index(row);
				m_CreatingLoadedListMode->setData(index, fileName);
				ui.listView_WaitingLoadModule->setCurrentIndex(index);
			}
			else
			{
				QMessageBox::critical(nullptr, u8"错误", u8"添加DLL失败");
			}
		}
		else
		{
			QMessageBox::critical(nullptr, u8"错误", u8"dll路径太长！");
		}	
	}
}

void CCDrvKit_App::PushButton_RemoveModule_Clicked()
{
	auto row = ui.listView_WaitingLoadModule->currentIndex().row();
	if (row != -1)
	{
		auto data = m_CreatingLoadedListMode->itemData(ui.listView_WaitingLoadModule->currentIndex());
		auto path = data.value(0).toString().toStdWString();
		

		DK_CMD cmd;

		ZeroMemory(&cmd, sizeof(cmd));
		cmd.Opertion = OPERTION::eOption_RemoveDllItem;
		wcsncpy_s(cmd.Cmd.REMOVE_DLL_ITEM_CMDLINE.DllPath, path.c_str(), path.size());

		if (m_DrvKitManager->SendCmd(&cmd))
		{
			m_CreatingLoadedListMode->removeRow(row);
		}
	}
}

void CCDrvKit_App::PushButton_ClearModule_Clicked()
{
	DK_CMD cmd;
	cmd.Opertion = eOption_ClearAllDllItem;
	if (m_DrvKitManager->SendCmd(&cmd))
	{
		m_CreatingLoadedListMode->removeRows(0, m_CreatingLoadedListMode->rowCount());
	}
}

void CCDrvKit_App::PushButton_Existing_LoadModule_Clicked()
{
	QString fileName = QFileDialog::getOpenFileName(
		this,
		u8"请选择一个DLL文件",
		"C:\\",
		"(*.dll)");

	if (fileName.size() > 0)
	{
		if (fileName.size() < MAX_PATH_SIZE)
		{
			// 修正一下路径分隔符
			fileName.replace("/", "\\");

			DK_CMD cmd;
			ZeroMemory(&cmd, sizeof(cmd));
			auto text = ui.ComboBox_ProcList->currentText();
			auto beg = text.indexOf("(", 0) + 1;
			auto end = text.indexOf(")", beg);
			auto Pid = text.mid(beg, end - beg).toUInt();

			cmd.Opertion = eOption_LoadDll;
			cmd.Cmd.LOAD_DLL.ProcessId = Pid;
			auto path = fileName.toStdWString();
			wcsncpy_s(cmd.Cmd.LOAD_DLL.DllPath, path.c_str(), path.size());

			if (m_DrvKitManager->SendCmd(&cmd))
			{
				
			}
			else
			{
				
			}
		}
		else
		{
			QMessageBox::critical(nullptr, u8"错误", u8"dll路径太长！");
		}
	}
}

void CCDrvKit_App::PushButton_Existing_UnloadModule_Clicked()
{
	auto num = ui.treeWidget_Existing_Loaded_Module->topLevelItemCount();
	auto text = ui.ComboBox_ProcList->currentText();
	auto beg = text.indexOf("(", 0) + 1;
	auto end = text.indexOf(")", beg);
	auto Pid = text.mid(beg, end - beg).toUInt();
	
	for (uint32_t i = 0; i < num; i++)
	{
		auto item = ui.treeWidget_Existing_Loaded_Module->topLevelItem(i);
		if (item->checkState(0) == Qt::Checked)
		{
			bool ok;
			uint64_t loadBaseAddr = item->text(1).toULongLong(&ok, 16);

			if (ok)
			{
				DK_CMD cmd;
				cmd.Opertion = eOption_UnloadDll;
				cmd.Cmd.UNLOAD_DLL.Force = ui.checkBox_Existed_ForceUnload->checkState() == Qt::Checked;
				cmd.Cmd.UNLOAD_DLL.ProcessId = Pid;
				cmd.Cmd.UNLOAD_DLL.LoadBaseAddress = loadBaseAddr;

				m_DrvKitManager->SendCmd(&cmd);
			}
		}
	}

	ui.treeWidget_Existing_Loaded_Module->clear();
	EnumModuleList(Pid);
}

void CCDrvKit_App::CheckBox_Creating_LoadModule_Clicked(bool checked)
{
	DK_CMD cmd;

	ZeroMemory(&cmd, sizeof(cmd));
	cmd.Cmd.CANCEL_LOAD_CREATING_PROCESS_CMDLINE.Value = !checked;
	cmd.Opertion = eOption_CancelLoadingCreatingProcess;
	m_DrvKitManager->SendCmd(&cmd);
}

void CCDrvKit_App::ComboBox_ProcList_Activated(int index)
{
	ui.ComboBox_ProcList->clear();
	EnumProcessList();
}

void CCDrvKit_App::ComboBox_ProcList_Activated(QString text)
{
	ui.ComboBox_ProcList->setCurrentText(text);

	auto beg = text.indexOf("(", 0) + 1;
	auto end = text.indexOf(")", beg);
	auto Pid = text.mid(beg, end - beg).toUInt();
	
	ui.treeWidget_Existing_Loaded_Module->clear();
	EnumModuleList(Pid);
}

void CCDrvKit_App::ComboBox_ProcList_Highlighted(QString text)
{
	auto tx = ui.ComboBox_ProcList->currentText();
	EnumProcessList();
	ui.ComboBox_ProcList->setCurrentText(tx);
}

void CCDrvKit_App::ListView_WaitingLoad_DropEvet(QDropEvent* event)
{
	/*const QMimeData* mimeData = event->mimeData();
	if (mimeData->hasUrls())
	{
		QList<QUrl> urlList = mimeData->urls();
		QStringList list;
		for (const QUrl& url : urlList) {
			list.append(url.toLocalFile());
			qDebug() << u8"拖拽的文件路径：" << url.toLocalFile();
		}
	}*/
}
