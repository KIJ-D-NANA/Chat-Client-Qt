#ifndef CONNECTWINDOW_H
#define CONNECTWINDOW_H

#include <QMainWindow>

namespace Ui {
class ConnectWindow;
}

class ConnectWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit ConnectWindow(QWidget *parent = 0);
    ~ConnectWindow();

private:
    Ui::ConnectWindow *ui;

    const char* CA =
"-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlddRwveTRS0/9n8axoeO\n\
+BwvuRLlIgsvdQ95dmwmOHyXV5zpDyqqdWOFghdh0KXb9KayFoiIluzTjCI206WD\n\
/F/MIot8BFVf0sYfnaq9WUyKmg+YtZ1qhkov/Yk5GDu/hJew+8+rxNx/dokZhLTn\n\
kCiktDHLAQAoSv7dMMdN1Ad/eVj4qRd3cXfFFbgOfJI2Mkpb62glIsUvULE38vvh\n\
Yz2ylKc7c0Z07oK+yxPMh+sOMcTrzpQ617ov0V/NrFpcoqeDhTs/Lkln4v2OtYzn\n\
KtOIlHQOKXdQSibaZn+OjTlfDok+EtIf6wgtlh8j1JfxPsUjRKyb6qPfb1sFAwjM\n\
+QIDAQAB\n\
-----END PUBLIC KEY-----";

public slots:
    void ConnectToHost();
};

#endif // CONNECTWINDOW_H
