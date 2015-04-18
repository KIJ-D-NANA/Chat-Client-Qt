#ifndef CONNECTION_H
#define CONNECTION_H

#include <QObject>
#include <QTcpSocket>
#include <QTimer>
#include <string>
#include <openssl/rsa.h>
#include "rc4algorithm.h"
#include "sha1hash.h"
#include "rsacrpto.h"

#include "rsaalgorithm.h"

class Connection : public QObject
{
    Q_OBJECT
public:
    explicit Connection(int refreshRate_msec = 1000, QObject *parent = 0);
    ~Connection();
    bool connectToHost(QString IP, quint16 Port, QString Username);
    void setServerKeyPair(const char* key, int key_len);

    void getPubKey(QString name);
private:
    QTimer timer;
    SHA1Hash HashEngine;
    QTcpSocket* socket;
    bool isApplicationRunning;
    QString username;
    RSACrpto ServKey;
    RSACrpto ClientKey;

    static constexpr char* alphabet =
"abcdefghijklmnopqrstuvwxyz\
ABCDEFGHIJKLMNOPQRSTUVWXYZ\
0123456789";
    RC4Algorithm* rc4;

private:
    std::string randomStringGen(size_t LEN);
    void SetRC4Key();
    void postPubKey();

signals:

public slots:
    void incomingMessage();
    void checkUserList();
    void disconnected();
    void outgoingPublicMessage(QString messageContent);
    void outgoingPrivateMessage(QString receiver, QString messageContent, RC4Algorithm* ClientRC4Key);
    void newPrivateWindow(QObject* privateWindow);
    void newSessionHandler(QObject* sender);
};

#endif // CONNECTION_H
