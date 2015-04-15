#ifndef CONNECTION_H
#define CONNECTION_H

#include <QObject>
#include <QTcpSocket>
#include <QTimer>
#include <string>
#include <openssl/rsa.h>
#include "rc4algorithm.h"

#include "rsaalgorithm.h"

class Connection : public QObject
{
    Q_OBJECT
public:
    explicit Connection(int refreshRate_msec = 1000, QObject *parent = 0);
    ~Connection();
    bool connectToHost(QString IP, quint16 Port, QString Username);
    void setServerKeyPair(const char* key, size_t key_len);
    int InitRSA();
    void getPubKey(QString name);
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
    RC4Algorithm* rc4;

private:
    std::string randomStringGen(size_t LEN);
    void SetRC4Key();
    void postPubKey();
    bool checkIntegrity(QString raw, QString hash);
    bool checkIntegrity(size_t input_len, unsigned char* raw, char* hash_string);
    QString toSHA1(QString data);
    QString toSHA1(std::string data);
    QString toSHA1(const char* data, size_t data_len);

signals:

public slots:
    void incomingMessage();
    void checkUserList();
    void disconnected();
    void outgoingPublicMessage(QString messageContent);
    void outgoingPrivateMessage(QString receiver, QString messageContent, RC4Algorithm* ClientRC4Key);
    void newPrivateWindow(QObject* privateWindow);
    void newSessionHandler(QString receiver, QObject* sender);
};

#endif // CONNECTION_H
