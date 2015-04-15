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
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>

Connection::Connection(int refreshRate_msec, QObject *parent) : QObject(parent)
{
    timer.setInterval(refreshRate_msec);
    this->InitRSA();
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
        QString sha_name = this->toSHA1(Username);
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

void Connection::newSessionHandler(QString receiver, QObject *sender){
    //TODO: Initiate new session to that user
    PrivateChat* privateChat = (PrivateChat*)sender;
    privateChat->InitiateRC4(randomStringGen(1024 / 8 - 40));
    QString message("Mode: GetPubKey\r\nUser: " + privateChat->getReceiver() + "\r\n.\r\n");
    socket->write(message.toUtf8());
}

void Connection::outgoingPublicMessage(QString messageContent){
    PublicChat* thePublic = (PublicChat*)parent();
    RC4Algorithm *rc4 = thePublic->getRC4();
    QString encryptedContent= rc4->crypt(messageContent);
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
            PublicWindow->addMessage(newString, mesg);
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
                destination->addMessage(stringList.at(2));
            }
            else{
                destination = PublicWindow->addPrivateChat(username);
                connect(destination, SIGNAL(sendMessage(QString,QString,RC4Algorithm*)), this, SLOT(outgoingPrivateMessage(QString,QString,RC4Algorithm*)));
                destination->addMessage(stringList.at(2));
            }
            destination->show();
//            destination->activateWindow();

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
                BIO* bufio;
                RSA* clientKey;
                QByteArray ba = stringList.at(2).toLatin1();
                bufio = BIO_new_mem_buf((void*)ba.data(), stringList.at(2).length());
                PEM_read_bio_RSAPublicKey(bufio, &clientKey, NULL, NULL);
                BIO_free_all(bufio);
                if(destination->cryptedKey != ""){
                    QByteArray ba2 = destination->cryptedKey.toLatin1();
                    char decrypted[4096];
                    int decrypt_len = RSA_public_decrypt(destination->cryptedKey.length(), (unsigned char*)ba2.data(), (unsigned char*)decrypted, clientKey, RSA_PKCS1_PADDING);
                    decrypted[decrypt_len] = '\0';
                    char* hash_value = strstr(decrypted, "\r\n.,\r\n");
                    *hash_value = '\0';
                    hash_value = hash_value + 6;
                    if(this->checkIntegrity(QString::fromUtf8(decrypted), QString::fromUtf8(hash_value))){
                        destination->InitiateRC4(std::string(decrypted));
                        destination->setInitiateStatus(true);
                        QString random_message = QString::fromStdString(this->randomStringGen(200));
                        QString random_hash = this->toSHA1(random_message);
                        QString content = destination->getRC4()->crypt(random_message + "\r\n.,\r\n" + random_hash);
                        socket->write("Mode: AccPriv\r\nUser: " + destination->getReceiver() + "\r\n" + content + "\r\n.\r\n");
                    }
                }
                else{
                    string clientrc4 = this->randomStringGen(1024 / 8 - 40);
                    QString hash_value = this->toSHA1(clientrc4);
                    QString To_encrypt = QString::fromStdString(clientrc4) + "\r\n.,\r\n" + hash_value;
                    QByteArray ba2 = To_encrypt.toLatin1();
                    char encrypt[4096];
                    int encrypt_len = RSA_private_encrypt(encrypt.length(), (unsigned char*)ba2.data(), (unsigned char*)encrypt, keypair, RSA_PKCS1_PADDING);
                    char encrypt2[4096];
                    int encrypt2_len = RSA_public_encrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)encrypt2, clientKey, RSA_PKCS1_OAEP_PADDING);
                    QString message("Mode: InitPriv\r\nUser: " + destination->getReceiver() + "\r\n" + QString::fromUtf8(encrypt2, encrypt2_len) + "\r\n.\r\n");
                    socket->write(message.toUtf8());
                }
            }
        }
        else if(stringList.at(2) == "Mode: AccPriv"){
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
                if(this->checkIntegrity(thePair.at(0), thePair.at(1))){
                    destination->setInitiateStatus(true);
                }
            }
        }

    }
}

void Connection::outgoingPrivateMessage(QString receiver, QString messageContent, RC4Algorithm *ClientRC4Key){
    QString message_hash = this->toSHA1(messageContent);
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
//    privateChat->InitiateRC4(randomStringGen(1024 / 8 - 40));
    QString message("Mode: GetPubKey\r\nUser: " + privateChat->getReceiver() + "\r\n.\r\n");
    socket->write(message.toUtf8());
}

void Connection::setServerKeyPair(const char *key, size_t key_len){
    BIO* bufio;
    bufio = BIO_new_mem_buf((void*)key, key_len);
    PEM_read_bio_RSAPublicKey(bufio, &ServKey, NULL, NULL);
    BIO_free_all(bufio);
}

int Connection::InitRSA(){
    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4);
    int r = RSA_generate_key_ex(keypair, 2048, bne, NULL);
    BN_free(bne);
    return r;
}

std::string Connection::randomStringGen(size_t LEN){
    std::random_device rd;
    std::default_random_engine rng(rd());
    std::uniform_int_distribution<> dist(0,sizeof(alphabet)/sizeof(*alphabet)-2);

    std::string strs;
    strs.reserve(LEN);
    std::generate_n(strs.begin(), LEN, [&](){return alphabet[dist(rng)];});
    return strs;
}

void Connection::postPubKey(){
    // Sending Public key to the server
    size_t pub_len;
    char* pub_key;
    BIO* pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub, keypair);
    pub_len = BIO_pending(pub);
    pub_key = (char*) malloc(pub_len + 1);
    BIO_read(pub, pub_key, pub_len);
    pub_key[pub_len] = '\0';
    QString sha_value = this->toSHA1(pub_key, pub_len);
    QString content = this->rc4->crypt(QString::fromUtf8(pub_key, pub_len) + "\r\n.,\r\n" + sha_value);
    QString message("Mode: SetPubKey\r\n" + content + "\r\n.\r\n");
    socket->write(message.toUtf8());
    free(pub_key);
    BIO_free_all(pub);
    //
}

void Connection::SetRC4Key(){
    std::string rc4key = randomStringGen(1024 / 8 - 40);
    this->rc4 = new RC4Algorithm(rc4key);
    //TODO: Send key to server
    QString key_hash = this->toSHA1(rc4key);
    QString raw_data = QString::fromStdString(rc4key) + "\r\n.,\r\n" + key_hash;
    QByteArray ba = raw_data.toLatin1();
    char* toEncrypted = ba.data();
    char encrypt[4096];
    int encrypt_len = RSA_public_encrypt(raw_data.length(), (unsigned char*)toEncrypted, (unsigned char*)encrypt, ServKey, RSA_PKCS1_OAEP_PADDING);
    QString message = "Mode: SetRC4Key\r\n";
    for(int i = 0; i < encrypt_len; i++)
        message += *(encrypt + i);
    message += "\r\n.\r\n";
    socket->write(message.toUtf8());
}

bool Connection::checkIntegrity(QString raw, QString hash){
//    char raw_cstr[raw.length()];
    QByteArray ba = raw.toLatin1();
    char* temp = ba.data();
    QByteArray ba2 = hash.toLatin1();
    char* temp2 = ba2.data();
    return this->checkIntegrity(raw.length(), (unsigned char*)temp, temp2);
}

bool Connection::checkIntegrity(size_t input_len, unsigned char *raw, char *hash_string){
    char hash_out[SHA_DIGEST_LENGTH + 1];
    char hash_value[SHA_DIGEST_LENGTH * 2 + 1];
    SHA1(raw, input_len, (unsigned char*)hash_out);
    for(int i = 0; i < SHA_DIGEST_LENGTH; i++){
        sprintf(&hash_value[i * 2], "%02x", (unsigned int)hash_out[i]);
    }
    return strcmp(hash_value, hash_string) == 0 ? true : false;
}

QString Connection::toSHA1(QString data){
    QByteArray ba = data.toLatin1();
    return this->toSHA1(ba.data(), data.length());
}

QString Connection::toSHA1(string data){
    return this->toSHA1(data.c_str(), data.size());
}

QString Connection::toSHA1(const char *data, size_t data_len){
    char hash_out[SHA_DIGEST_LENGTH + 1];
    char hash_value[SHA_DIGEST_LENGTH * 2 + 1];
    SHA1((unsigned char*)data, data_len, (unsigned char*)hash_out);
    for(int i = 0; i < SHA_DIGEST_LENGTH; i++){
        sprintf(&hash_value[i * 2], "%02x", (unsigned int)hash_out[i]);
    }
    return QString::fromUtf8(hash_value);
}
