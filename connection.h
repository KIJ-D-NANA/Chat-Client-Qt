#ifndef CONNECTION_H
#define CONNECTION_H

#include <QObject>
#include <QTcpSocket>
#include <QTimer>
#include <openssl/rsa.h>
#include "rsaalgorithm.h"
class Connection : public QObject
{
    Q_OBJECT
public:
    explicit Connection(int refreshRate_msec = 1000, QObject *parent = 0);
    ~Connection();
    bool connectToHost(QString IP, quint16 Port, QString Username);
    int InitRSA();
    void getPubKey(QString name);
private:
    QTimer timer;
    QTcpSocket* socket;
    bool isApplicationRunning;
    QString username;
    RSAAlgorithm* rsa;
    char* CA= "-----BEGIN PUBLIC KEY-----\n"
                       "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlddRwveTRS0/9n8axoeO\n"
                       "+BwvuRLlIgsvdQ95dmwmOHyXV5zpDyqqdWOFghdh0KXb9KayFoiIluzTjCI206WD\n"
                       "/F/MIot8BFVf0sYfnaq9WUyKmg+YtZ1qhkov/Yk5GDu/hJew+8+rxNx/dokZhLTn\n"
                       "kCiktDHLAQAoSv7dMMdN1Ad/eVj4qRd3cXfFFbgOfJI2Mkpb62glIsUvULE38vvh\n"
                       "Yz2ylKc7c0Z07oK+yxPMh+sOMcTrzpQ617ov0V/NrFpcoqeDhTs/Lkln4v2OtYzn\n"
                       "KtOIlHQOKXdQSibaZn+OjTlfDok+EtIf6wgtlh8j1JfxPsUjRKyb6qPfb1sFAwjM\n"
                       "+QIDAQAB\n"
                       "-----END PUBLIC KEY-----";
signals:

public slots:
    void incomingMessage();
    void checkUserList();
    void disconnected();
    void outgoingPublicMessage(QString messageContent);
    void outgoingPrivateMessage(QString receiver, QString messageContent);
    void newPrivateWindow(QObject* privateWindow);
};

#endif // CONNECTION_H
