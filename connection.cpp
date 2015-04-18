#include "connection.h"
#include "publicchat.h"
#include "privatechat.h"
#include <QMessageBox>
#include <QDebug>
#include <iostream>
#include <iterator>
#include <vector>
#include <random>
#include <algorithm>
#include <stdio.h>

Connection::Connection(int refreshRate_msec, QObject *parent) : QObject(parent)
{
    timer.setInterval(refreshRate_msec);
    ClientKey.InitKey(2048);
    connect(&timer, SIGNAL(timeout()), this, SLOT(checkUserList()));
    isApplicationRunning = false;
}

Connection::~Connection()
{

}

bool Connection::connectToHost(QString IP, quint16 Port, QString Username){
    socket = new QTcpSocket(this);
    qDebug() << Username;
    this->username = Username;
    connect(socket, SIGNAL(readyRead()), this, SLOT(incomingMessage()));
    socket->connectToHost(IP, Port);
    if(socket->waitForConnected()){
        connect(socket, SIGNAL(disconnected()), this, SLOT(disconnected()));
        PublicChat* thePublic = (PublicChat*)parent();
        connect(thePublic, SIGNAL(sendMessage(QString)), this, SLOT(outgoingPublicMessage(QString)));
        isApplicationRunning = true;
        this->SetRC4Key();
        this->postPubKey();
        qDebug() << "Stop Here!!";
        //TODO: Encrypt the username
        QString sha_name = HashEngine.toSHA1(Username);
        QString encrypted = rc4->crypt(Username + "\r\n.,\r\n" + sha_name);
        socket->write("Mode: Username\r\n" + encrypted.toUtf8() + "\r\n.\r\n");

        timer.start();
        return true;
    }
    return false;
}

void Connection::disconnected(){
    if(isApplicationRunning){
        QMessageBox alert;
        alert.setWindowTitle("Disconnected");
        alert.setText("You have been disconnected from server\nTrying to reconnect");

        alert.exec();
        while(!socket->reset() && isApplicationRunning);
        socket->write(username.toUtf8() + "\r\n.\r\n");
    }
    else{
        socket->deleteLater();
    }
}

void Connection::newSessionHandler(QObject *sender){
    //TODO: Initiate new session to that user
    PrivateChat* privateChat = (PrivateChat*)sender;
    privateChat->InitiateRC4(randomStringGen(4));
    QString message("Mode: GetPubKey\r\nUser: " + privateChat->getReceiver() + "\r\n.\r\n");
    socket->write(message.toUtf8());
}

void Connection::outgoingPublicMessage(QString messageContent){
    PublicChat* thePublic = (PublicChat*)parent();
    RC4Algorithm *rc4 = thePublic->getRC4();
    QString hash_value = HashEngine.toSHA1(messageContent);
    QString encryptedContent= rc4->crypt(messageContent + "\r\n.,\r\n" + hash_value);
    qDebug() << encryptedContent;
    QString message("Mode: Public\r\n" + encryptedContent + "\r\n.\r\n");
    socket->write(message.toUtf8());
}

void Connection::incomingMessage(){
    QByteArray data = socket->readAll();
    QString message(data);
    PublicChat* PublicWindow = (PublicChat*)parent();
    for(const QString oneMessage : message.split("\r\n.\r\n")){
        if(oneMessage == NULL) continue;
        QStringList stringList = oneMessage.split("\r\n");
        if(stringList.at(0) == "Mode: Public"){
            //Send message to the window
            //'User: '/
            QString newString = stringList.at(1);
            newString.remove(0, 6);
            PublicChat* thePublic = (PublicChat*)parent();
            qDebug() << stringList.at(2);
            RC4Algorithm *rc4 = thePublic->getRC4();
            QString mesg = rc4->crypt(stringList.at(2));
            QStringList content = mesg.split("\r\n.,\r\n");
            if(!content.isEmpty()){
                if(HashEngine.checkIntegrity(content.at(0), content.at(1)))
                    PublicWindow->addMessage(newString, content.at(0));
            }
        }
        else if(stringList.at(0) == "Mode: Private"){
            //Check private window
            //Create new window if necessary
            QString username = stringList.at(1);
            username.remove(0, 6);

            PrivateChat* destination = nullptr;
            for(PrivateChat* now : *(PublicWindow->getPrivateChatList())){
                if(now->getReceiver() == username){
                    destination = now;
                    break;
                }
            }
            //Send message to the window
            if(destination != nullptr){
                if(destination->getInitiateStatus()){
                    QString decrypted = destination->getRC4()->crypt(stringList.at(2));
                    QStringList content = decrypted.split("\r\n.,\r\n");
                    if(!content.isEmpty()){
                        if(HashEngine.checkIntegrity(content.at(0), content.at(1)))
                            destination->addMessage(content.at(0));
                    }
                }
            }

        }
        else if(stringList.at(0) == "Mode: List"){
            //Contain user list in QStringList
            //Send the list to PublicChat
            QStringList newList(stringList);
            newList.removeFirst();
            PublicWindow->updateUserList(newList);
        }
        else if(stringList.at(0) == "Mode: ClientPubKey"){
            QString username = stringList.at(1);
            username.remove(0, 6);
            PrivateChat* destination = nullptr;
            for(PrivateChat* now : *(PublicWindow->getPrivateChatList())){
                if(now->getReceiver() == username){
                    destination = now;
                    break;
                }
            }
            if(destination != nullptr && !destination->getInitiateStatus()){
                //Have been reworked
                QStringList content = rc4->crypt(stringList.at(2)).split("\r\n.,\r\n");
                if(!content.isEmpty() && HashEngine.checkIntegrity(content.at(0), content.at(1))){
                    RSACrpto otherKey;
                    otherKey.setPubKey(content.at(0));
                    //If this is the receiver
                    if(destination->cryptedKey != "" && !destination->initiator){
                        QStringList keyMessage = otherKey.public_decrypt(destination->cryptedKey).split("\r\n.,\r\n");
                        if(!keyMessage.isEmpty() && HashEngine.checkIntegrity(keyMessage.at(0), keyMessage.at(1))){
                            destination->InitiateRC4(keyMessage.at(0).toStdString());
                            std::string random_message = this->randomStringGen(200);
                            QString random_hash = HashEngine.toSHA1(random_message);
                            QString send_content = rc4->crypt(QString::fromStdString(random_message) + "\r\n.,\r\n" + random_hash);
                            QString message("Mode: AccPriv\r\nUser: " + destination->getReceiver() + "\r\n" + send_content + "\r\n.\r\n");
                            destination->setInitiateStatus(true);
                            socket->write(message.toUtf8());
                        }
                        else{
                            PublicWindow->getPrivateChatList()->removeOne(destination);
                            delete destination;
                        }
                    }
                    //if this is the initiator
                    else{
                        std::string client_rc4_key = randomStringGen(20);
                        destination->InitiateRC4(client_rc4_key);
                        QString key_hash = HashEngine.toSHA1(client_rc4_key);
                        QString layer1_encrypt = ClientKey.private_encrypt(QString::fromStdString(client_rc4_key) + "\r\n.,\r\n" + key_hash);
                        QString layer2_encrypt = otherKey.public_encrypt(layer1_encrypt);
                        QString message("Mode: InitPriv\r\nUser: " + destination->getReceiver() + "\r\n" + layer2_encrypt + "\r\n.\r\n");
                        socket->write(message.toUtf8());
                    }
                }
            }
        }
        else if(stringList.at(0) == "Mode: AccPriv"){
            QString username = stringList.at(1);
            username.remove(0, 6);
            PrivateChat* destination = nullptr;
            for(PrivateChat* now : *(PublicWindow->getPrivateChatList())){
                if(now->getReceiver() == username){
                    destination = now;
                    break;
                }
            }
            if(destination != nullptr && destination->initiator && !destination->getInitiateStatus()){
                QString decrypted = destination->getRC4()->crypt(stringList.at(2));
                QStringList thePair = decrypted.split("\r\n.,\r\n");
                if(!thePair.empty()){
                    if(HashEngine.checkIntegrity(thePair.at(0), thePair.at(1))){
                        destination->setInitiateStatus(true);
                    }
                }
            }
        }
        else if(stringList.at(0) == "Mode: InitPriv"){
            QString username = stringList.at(1);
            username.remove(0, 6);
            PrivateChat* destination = nullptr;
            for(PrivateChat* now : *(PublicWindow->getPrivateChatList())){
                if(now->getReceiver() == username){
                    destination = now;
                    break;
                }
            }
            if(destination == nullptr){
                destination = PublicWindow->addPrivateChat(username);
                QString decrypt = ClientKey.private_decrypt(stringList.at(2));
                destination->cryptedKey = decrypt;
                destination->initiator = false;
                QString message("Mode: GetPubKey\r\nUser: " + username + "\r\n.\r\n");
                socket->write(message.toUtf8());
            }
        }
    }
}
void Connection::getPubKey(QString name){
    QString message("Mode: GetPubKey\r\nUser: " + name + "\r\n.\r\n");
    socket->write(message.toUtf8());
}

void Connection::outgoingPrivateMessage(QString receiver, QString messageContent, RC4Algorithm *ClientRC4Key){
    QString message_hash = HashEngine.toSHA1(messageContent);
    QString content = ClientRC4Key->crypt(messageContent + "\r\n.,\r\n" + message_hash);
    QString message("Mode: Private\r\nUser: " + receiver + "\r\n" + content + "\r\n.\r\n");
    socket->write(message.toUtf8());
}

void Connection::checkUserList(){
    QString message("Mode: GetList\r\n.\r\n");
    socket->write(message.toUtf8());
}

void Connection::newPrivateWindow(QObject *privateWindow){
    //Add signal listener to the new window
    PrivateChat* privateChat = (PrivateChat*)privateWindow;
    connect(privateChat, SIGNAL(sendMessage(QString,QString,RC4Algorithm*)), this, SLOT(outgoingPrivateMessage(QString,QString,RC4Algorithm*)));
    // TODO : Distribute key with another client
    QString message("Mode: GetPubKey\r\nUser: " + privateChat->getReceiver() + "\r\n.\r\n");
    socket->write(message.toUtf8());
}


void Connection::setServerKeyPair(const char *key, int key_len){
    ServKey.setPubKey(key, key_len);
}

std::string Connection::randomStringGen(size_t LEN){
    int length = LEN;
    auto randchar = []() -> char
    {
        const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[ rand() % max_index ];
    };
    std::string str(length,0);
    std::generate_n( str.begin(), length, randchar );
    return str;
}

void Connection::postPubKey(){
    // Sending Public key to the server
    QString public_key = ClientKey.getPubKey();
    QString public_hash = HashEngine.toSHA1(public_key);
    QString content = rc4->crypt(public_key + "\r\n.,\r\n" + public_hash);
    QString message("Mode: SetPubKey\r\n" + content + "\r\n.\r\n");
    socket->write(message.toUtf8());
    //
}

void Connection::SetRC4Key(){
    std::string rc4key = randomStringGen(20);
    this->rc4 = new RC4Algorithm(rc4key);
    QString key_hash = HashEngine.toSHA1(rc4key);
    QString content = ServKey.public_encrypt(QString::fromStdString(rc4key) + "\r\n.,\r\n" + key_hash);
    QString message("Mode: SetRC4Key\r\n" + content + "\r\n.\r\n");
    socket->write(message.toUtf8());
}
