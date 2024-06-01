#include "CCDrvKit_App.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
	
	CCDrvKit_App w;
	w.show();
	w.EnumProcessList();
    return a.exec();
}
