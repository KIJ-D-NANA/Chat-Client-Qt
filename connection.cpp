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
#include "base64engine.h"

Connection::Connection(int refreshRate_msec, QObject *parent) : QObject(parent)
{
    timer.setInterval(refreshRate_msec);
    ClientKey.InitKey(2048);
    qDebug() << ClientKey.getPubKey();
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
        //TODO: Encrypt the username
        QString sha_name = HashEngine.toSHA1(Username);
        QString encrypted = rc4->crypt(Username + "\r\n.,\r\n" + sha_name);
        QString encoded = Base64Engine::encode(encrypted);
        socket->write("Mode: Username\r\n" + encoded.toUtf8() + "\r\n.\r\n");
        socket->flush();

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
    QString encoded_crypt = Base64Engine::encode(encryptedContent);
//    qDebug() << encryptedContent;
    QString message("Mode: Public\r\n" + encoded_crypt + "\r\n.\r\n");
    socket->write(message.toUtf8());
    socket->flush();
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
            char* decoded;
            int decoded_len = Base64Engine::decode(stringList.at(2).toLatin1().data(), (unsigned char**)&decoded, stringList.at(2).length());
            QString mesg = rc4->crypt(decoded, decoded_len);
            free(decoded);
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
                    char* decoded;
                    int decoded_len = Base64Engine::decode(stringList.at(2).toLatin1().data(), (unsigned char**)&decoded, stringList.at(2).length());
                    QString decrypted = destination->getRC4()->crypt(decoded, decoded_len);
                    free(decoded);
                    QStringList content = decrypted.split("\r\n.,\r\n");
                    if(!content.isEmpty()){
                        if(HashEngine.checkIntegrity(content.at(0), content.at(1))){
                            destination->addMessage(content.at(0));
                            destination->show();
                        }
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
                char* public_decode;
                QByteArray public_bytearray = stringList.at(2).toLatin1();
                int public_decode_len = Base64Engine::decode(public_bytearray.data(), (unsigned char**)&public_decode, stringList.at(2).length());
                QString content_string = rc4->crypt(public_decode, public_decode_len);
                QStringList content = content_string.split("\r\n.,\r\n");
                free(public_decode);
                QString certificate = content.at(0).mid(0, content.at(0).length() - 1);
                qDebug() << certificate;
//                bool theIntegrity = HashEngine.checkIntegrity(content.at(0), content.at(1));
                if(!content.isEmpty() && content.length() == 2){
                    RSACrpto otherKey;
                    otherKey.setPubKey(content.at(0));
                    //If this is the receiver
                    if(destination->cryptedKey != "" && !destination->initiator){
                        char* decoded;
                        QByteArray byteArray = destination->cryptedKey.toLatin1();
                        int decode_len = Base64Engine::decode(byteArray.data(), (unsigned char**)&decoded, destination->cryptedKey.length());

                        char* decrypted;
                        int decrypt_len = otherKey.public_decrypt(decoded, decode_len, &decrypted, RSA_PKCS1_PADDING);
                        QStringList keyMessage = QString::fromUtf8(decrypted, decrypt_len).split("\r\n.,\r\n");
                        free(decoded);
                        free(decrypted);
                        bool key_integrity = HashEngine.checkIntegrity(keyMessage.at(0), keyMessage.at(1));
                        if(!keyMessage.isEmpty() && key_integrity){
                            destination->InitiateRC4(keyMessage.at(0).toStdString());
                            std::string random_message = this->randomStringGen(200);
                            QString random_hash = HashEngine.toSHA1(random_message);
                            QString send_content = destination->getRC4()->crypt(QString::fromStdString(random_message) + "\r\n.,\r\n" + random_hash);
                            QString encoded_content = Base64Engine::encode(send_content);
                            QString message("Mode: AccPriv\r\nUser: " + destination->getReceiver() + "\r\n" + encoded_content + "\r\n.\r\n");
                            qDebug() << message;
                            destination->setInitiateStatus(true);
                            connect(destination, SIGNAL(sendMessage(QString,QString,RC4Algorithm*)), this, SLOT(outgoingPrivateMessage(QString,QString,RC4Algorithm*)));
                            socket->write(message.toUtf8());
                            socket->flush();
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
                        char* layer1;
                        int layer1_len = ClientKey.private_encrypt(QString::fromStdString(client_rc4_key) + "\r\n.,\r\n" + key_hash, &layer1, RSA_PKCS1_PADDING);
                        char* layer2;
                        int layer2_len = otherKey.public_encrypt(layer1, layer1_len, &layer2, RSA_NO_PADDING);
                        QString layer2_encrypt = Base64Engine::encode(layer2, layer2_len);

                        free(layer1);
                        free(layer2);

                        QString message("Mode: InitPriv\r\nUser: " + destination->getReceiver() + "\r\n" + layer2_encrypt + "\r\n.\r\n");
                        qDebug() << message;
                        socket->write(message.toUtf8());
                        socket->flush();
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
                char* decoded;
                int decoded_len = Base64Engine::decode(stringList.at(2).toLatin1().data(), (unsigned char**)&decoded, stringList.at(2).length());
                QString decrypted = destination->getRC4()->crypt(decoded, decoded_len);
                free(decoded);
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
                char* decoded;
                int decoded_len = Base64Engine::decode(stringList.at(2).toLatin1().data(), (unsigned char**)&decoded, stringList.at(2).length());
                char* decrypted;
                int decrypt_len = ClientKey.private_decrypt(decoded, decoded_len, &decrypted, RSA_NO_PADDING);
                destination->cryptedKey = Base64Engine::encode(decrypted, decrypt_len);

                free(decrypted);
                free(decoded);

                destination->initiator = false;
                QString message("Mode: GetPubKey\r\nUser: " + username + "\r\n.\r\n");
                socket->write(message.toUtf8());
                socket->flush();
            }
        }
    }
}
void Connection::getPubKey(QString name){
    QString message("Mode: GetPubKey\r\nUser: " + name + "\r\n.\r\n");
    socket->write(message.toUtf8());
    socket->flush();
}

void Connection::outgoingPrivateMessage(QString receiver, QString messageContent, RC4Algorithm *ClientRC4Key){
    QString message_hash = HashEngine.toSHA1(messageContent);
    QString content = ClientRC4Key->crypt(messageContent + "\r\n.,\r\n" + message_hash);
    QString encoded_content = Base64Engine::encode(content);
    QString message("Mode: Private\r\nUser: " + receiver + "\r\n" + encoded_content + "\r\n.\r\n");
    socket->write(message.toUtf8());
    socket->flush();
}

void Connection::checkUserList(){
    QString message("Mode: GetList\r\n.\r\n");
    socket->write(message.toUtf8());
    socket->flush();
}

void Connection::newPrivateWindow(QObject *privateWindow){
    //Add signal listener to the new window
    PrivateChat* privateChat = (PrivateChat*)privateWindow;
    connect(privateChat, SIGNAL(sendMessage(QString,QString,RC4Algorithm*)), this, SLOT(outgoingPrivateMessage(QString,QString,RC4Algorithm*)));
    // TODO : Distribute key with another client
    QString message("Mode: GetPubKey\r\nUser: " + privateChat->getReceiver() + "\r\n.\r\n");
    socket->write(message.toUtf8());
    socket->flush();
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
    QString encoded = Base64Engine::encode(content);
    QString message("Mode: SetPubKey\r\n" + encoded + "\r\n.\r\n");
    socket->write(message.toUtf8());
    socket->flush();
    //
}

void Connection::SetRC4Key(){
    std::string rc4key = randomStringGen(20);
    this->rc4 = new RC4Algorithm(rc4key);
    QString key_hash = HashEngine.toSHA1(rc4key);
    char* encrypted;
    int encrypted_len = ServKey.public_encrypt(QString::fromStdString(rc4key) + "\r\n.,\r\n" + key_hash, &encrypted);
    QString content = Base64Engine::encode(encrypted, encrypted_len);
    free(encrypted);

    QString message("Mode: SetRC4Key\r\n" + content + "\r\n.\r\n");
    socket->write(message.toUtf8());
    socket->flush();
}
