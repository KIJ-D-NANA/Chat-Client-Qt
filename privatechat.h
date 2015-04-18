#ifndef PRIVATECHAT_H
#define PRIVATECHAT_H

#include <QMainWindow>
#include <QTimer>
#include "rc4algorithm.h"

namespace Ui {
class PrivateChat;
}

class PrivateChat : public QMainWindow
{
    Q_OBJECT

public:
    explicit PrivateChat(QString username, int intervalMsec = 500, QWidget *parent = 0);
    ~PrivateChat();
    QString getReceiver();
    void setReceiver(QString messageReceiver);
    void setTimerIntrval(int msec);
    void addMessage(QString messageContent);
    void setInitiateStatus(bool status);
    bool getInitiateStatus();
    RC4Algorithm* getRC4();
    void InitiateRC4(std::string key);
    QString cryptedKey;

    bool initiator;

signals:
    void sendMessage(QString messageReceiver, QString messageContent, RC4Algorithm* ClientRC4Key);
    void windowClosed(QObject* window);
    void newSession(QObject* sender);

public slots:
    void checkMessageText();
    void checkReceiverStatus();

private:
    Ui::PrivateChat *ui;
    QString messageReceiver;
    QTimer timer;
    QString username;
    bool initiated;
    RC4Algorithm* rc4;

private:
    void showEvent(QShowEvent* event);
    void closeEvent(QCloseEvent* event);
    void addUserMessage(QString messageContent);
    void expireSession();
    void renewSession();
};

#endif // PRIVATECHAT_H
