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
        socket->write("Mode: Username\r\n" + Username.toUtf8() + "\r\n.\r\n");
        // Sending Public key to the server
        size_t pub_len;
        char* pub_key;
        BIO* pub = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPublicKey(pub, keypair);
        pub_len = BIO_pending(pub);
        pub_key = (char*) malloc(pub_len + 1);
        BIO_read(pub, pub_key, pub_len);
        pub_key[pub_len] = '\0';
        char* encrypt = (char*) malloc(4096);
        int encrypt_len = RSA_public_encrypt(pub_len, (unsigned char*)pub_key, (unsigned char*)encrypt, ServKey, RSA_PKCS1_OAEP_PADDING);
        encrypt[encrypt_len] = '\0';
        QString setPub("Mode: SetPubKey\r\n" + QString::fromUtf8(encrypt, encrypt_len) + "\r\n.\r\n");
        socket->write(setPub.toUtf8());
        free(encrypt);
        free(pub_key);
        BIO_free_all(pub);
        //

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
                connect(destination, SIGNAL(sendMessage(QString,QString)), this, SLOT(outgoingPrivateMessage(QString,QString)));
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
    }
}

void Connection::outgoingPrivateMessage(QString receiver, QString messageContent){
    QString message("Mode: Private\r\nUser: " + receiver + "\r\n" + messageContent + "\r\n.\r\n");
    socket->write(message.toUtf8());
}

void Connection::checkUserList(){
    QString message("Mode: GetList\r\n.\r\n");
    socket->write(message.toUtf8());
}

void Connection::newPrivateWindow(QObject *privateWindow){
    //Add signal listener to the new window
    PrivateChat* privateChat = (PrivateChat*)privateWindow;
    connect(privateChat, SIGNAL(sendMessage(QString,QString)), this, SLOT(outgoingPrivateMessage(QString,QString)));
    // TODO : Distribute key with another client
    privateChat->InitiateRC4(randomStringGen(1024 / 8 - 40));
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
    int r = RSA_generate_key_ex(keypair, 1024, bne, NULL);
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
