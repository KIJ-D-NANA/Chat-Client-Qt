#ifndef RSAALGORITHM_H
#define RSAALGORITHM_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <QObject>
#include <QMap>
#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS
#define WRITE_TO_FILE

class RSAAlgorithm
{
public:
    RSAAlgorithm();
    ~RSAAlgorithm();
    char* getPublicKey();
    void setServerKeyPair(char *key, size_t key_len);
    void setPubkeys(QString name, QString key);
private:
    RSA *keypair;
    BIO *pri;
    BIO *pub;
    size_t pri_len;
    size_t pub_len;
    char* pri_key;
    char* pub_key;
    RSA *servkey;
    QMap < QString, RSA* > pubkeys;
};

#endif // RSAALGORITHM_H
