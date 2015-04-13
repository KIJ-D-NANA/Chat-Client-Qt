#include "publicchat.h"
#include "ui_publicchat.h"
#include <QCloseEvent>
#include <QColor>
#include <QFont>
PublicChat::PublicChat(int maxCharacterLength, QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::PublicChat)
{
    ui->setupUi(this);

    this->setFixedSize(this->width(), this->height());

    connect(ui->message_box, SIGNAL(textChanged()), this, SLOT(MessageTextChanged()));
    connect(ui->message_box, SIGNAL(returnKeyPressed()), this, SLOT(checkMessage()));
    connect(ui->send_button, SIGNAL(clicked()), this, SLOT(checkMessage()));
    connect(ui->user_list, SIGNAL(itemDoubleClicked(QListWidgetItem*)), this, SLOT(createNewPrivateWindow(QListWidgetItem*)));
    maxCharacterMessageLength = maxCharacterLength;
    rc4 = new RC4Algorithm("test");
}

PublicChat::~PublicChat()
{
    delete ui;
}

void PublicChat::MessageTextChanged(){
    int length = ui->message_box->toPlainText().length();
    if(length > maxCharacterMessageLength){
        QString message = ui->message_box->toPlainText();
        message.remove(maxCharacterMessageLength, length - maxCharacterMessageLength);
        ui->message_box->setPlainText(message);
        ui->tex_number_label->setText(QString::number(maxCharacterMessageLength) + "/" + QString::number(maxCharacterMessageLength));
    }
    else{
        ui->tex_number_label->setText(QString::number(length) + "/" + QString::number(maxCharacterMessageLength));
    }
}

void PublicChat::checkMessage(){
    QString message = ui->message_box->toPlainText();
    this->addMessage(message);
    ui->message_box->clear();
    emit sendMessage(message);
}

void PublicChat::setUsername(QString username){
    this->username = username;
}

void PublicChat::PrivateWindowClosed(QObject *window){
//    privateList.removeOne((PrivateChat*) window);
    PrivateChat* theWindow = (PrivateChat*)window;
    if(!userList.contains(theWindow->getReceiver())){
        privateList.removeOne(theWindow);
        delete theWindow;
    }
}

void PublicChat::closeEvent(QCloseEvent *event){

    this->disconnect();
    for(PrivateChat* privateWindow : privateList){
        privateWindow->close();
    }
    event->accept();
}


void PublicChat::addMessage(QString username, QString messageContent){
    //Add message to TextBrowser
    ui->chat_box->setAlignment(Qt::AlignRight);
    ui->chat_box->setTextColor(Qt::red);
    ui->chat_box->setFontWeight(QFont::Bold);
    ui->chat_box->append(username + " :");
    ui->chat_box->setTextColor(Qt::black);
    ui->chat_box->setFontWeight(QFont::Normal);
    ui->chat_box->append(messageContent + "\n");
}

void PublicChat::addMessage(QString messageContent){
    ui->chat_box->setAlignment(Qt::AlignLeft);
    ui->chat_box->setTextColor(Qt::green);
    ui->chat_box->setFontWeight(QFont::Bold);
    ui->chat_box->append(this->username + " :");
    ui->chat_box->setTextColor(Qt::black);
    ui->chat_box->setFontWeight(QFont::Normal);
    ui->chat_box->append(messageContent + "\n");

}

void PublicChat::createNewPrivateWindow(QListWidgetItem *item){
    PrivateChat* newPrivateChat = new PrivateChat(this->username, 5000, this);
    newPrivateChat->initiator = true;
    newPrivateChat->setReceiver(item->text());
    newPrivateChat->show();
    privateList.append(newPrivateChat);
    connect(newPrivateChat, SIGNAL(windowClosed(QObject*)), this, SLOT(PrivateWindowClosed(QObject*)));
    emit newPrivateWindow((QObject*)newPrivateChat);
}

QStringList *PublicChat::getUserList(){
    return &userList;
}

QList<PrivateChat*>* PublicChat::getPrivateChatList(){
    return &privateList;
}

PrivateChat* PublicChat::addPrivateChat(QString username){
    PrivateChat* newPrivateWindow = new PrivateChat(username, 5000, this);
    newPrivateWindow->initiator = false;
    connect(newPrivateWindow, SIGNAL(windowClosed(QObject*)), this, SLOT(PrivateWindowClosed(QObject*)));
    privateList.append(newPrivateWindow);
//    newPrivateWindow->show();
    return newPrivateWindow;
}

void PublicChat::updateUserList(QStringList userList){
    this->userList = userList;
    ui->user_list->clear();
    ui->user_list->addItems(userList);
}

QString PublicChat::getUsername(){
    return this->username;
}
RC4Algorithm* PublicChat::getRC4(){
    return this->rc4;
}
