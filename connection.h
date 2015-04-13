#ifndef CONNECTION_H
#define CONNECTION_H

#include <QObject>
#include <QTcpSocket>
#include <QTimer>
#include <string>
#include <openssl/rsa.h>

class Connection : public QObject
{
    Q_OBJECT
public:
    explicit Connection(int refreshRate_msec = 1000, QObject *parent = 0);
    ~Connection();
    bool connectToHost(QString IP, quint16 Port, QString Username);
    void setServerKeyPair(const char* key, size_t key_len);
    int InitRSA();

private:
    QTimer timer;
    QTcpSocket* socket;
    bool isApplicationRunning;
    QString username;
    RSA* ServKey;
    RSA* keypair;
    static constexpr char* alphabet =
"abcdefghijklmnopqrstuvwxyz\
ABCDEFGHIJKLMNOPQRSTUVWXYZ\
0123456789";

private:
    std::string randomStringGen(size_t LEN);

signals:

public slots:
    void incomingMessage();
    void checkUserList();
    void disconnected();
    void outgoingPublicMessage(QString messageContent);
    void outgoingPrivateMessage(QString receiver, QString messageContent);
    void newPrivateWindow(QObject* privateWindow);
    void newSessionHandler(QString receiver, QObject* sender);
};

#endif // CONNECTION_H
