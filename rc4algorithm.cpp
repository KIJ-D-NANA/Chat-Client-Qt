#include "rc4algorithm.h"
#include <QDebug>
RC4Algorithm::RC4Algorithm(string key)
{
    for (int i=0; i<256; i++){
        S[i]=i;
        T[i]=key[i% key.length()];
    }
    initPermutation();
}

RC4Algorithm::~RC4Algorithm()
{
}

void RC4Algorithm::initPermutation()
{
    int j=0;
    for(int i=0;i<256;i++){
        j = (j+S[i]+T[i])%256;
        swap(S[i],S[j]);
    }
}

unsigned char RC4Algorithm::genKey(unsigned char* tempS)
{
    iter1 = (iter1+1) % 256;
    iter2 = (iter2+tempS[iter1]) % 256;
    swap(tempS[iter1],tempS[iter2]);
    int t = (tempS[iter1] + tempS[iter2]) % 256;
    return tempS[t];
}


QString RC4Algorithm::crypt(QString beforeText)
{
    qDebug() << beforeText.length();
    iter1=0;iter2=0;
    QString afterText;
    unsigned char tempS[256];
    copy(S,S+sizeof(S),tempS);
    for(int i=0;i<beforeText.length();i++){
          afterText += genKey(tempS) ^ beforeText[i].toLatin1();
    }
     qDebug() << afterText.length();
    return afterText;
}

QString RC4Algorithm::crypt(char *beforetext, int length){
    iter1 = iter2 = 0;
    QString afterText;
    unsigned char tempS[256];
    copy(S, S + sizeof(S), tempS);
    for(int i = 0; i < length; i++){
        afterText += genKey(tempS) ^ beforetext[i];
    }
    return afterText;
}
