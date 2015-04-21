#ifndef RC4ALGORITHM_H
#define RC4ALGORITHM_H
#include<QObject>
#include <string>
using namespace std;
class RC4Algorithm
{
public:
    RC4Algorithm(string key);
    ~RC4Algorithm();
    void initPermutation();
    unsigned char genKey(unsigned char* tempS);
    QString crypt(QString beforetext);
    QString crypt(char* beforetext, int length);
private:
    unsigned char S[256];
    unsigned char T[256];
    unsigned char K[256];
    int iter1;
    int iter2;
};

#endif // RC4ALGORITHM_H
