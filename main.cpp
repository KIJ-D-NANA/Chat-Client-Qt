#include "connectwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{

    QApplication a(argc, argv);
    ConnectWindow w;
    w.setWindowTitle("Connecting");
    w.show();


    return a.exec();
}
