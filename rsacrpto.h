#ifndef RSACRPTO_H
#define RSACRPTO_H
#include <QString>
#include <string>
#include <openssl/rsa.h>

class RSACrpto
{
public:
    RSACrpto();
    ~RSACrpto();
    RSA* InitKey(size_t key_len);

    bool setPubKey(QString public_key);
    bool setPubKey(std::string public_key);
    bool setPubKey(FILE* public_key);
    bool setPubKey(const char* public_key, int public_len = -1);

    bool setPrivateKey(QString private_key);
    bool setPrivateKey(std::string private_key);
    bool setPrivateKey(FILE* public_key);
    bool setPrivateKey(const char* private_key, int private_len = -1);

    QString public_encrypt(QString data, int padding = RSA_PKCS1_OAEP_PADDING);
    QString public_encrypt(std::string data, int padding = RSA_PKCS1_OAEP_PADDING);
    QString public_encrypt(const char* data, int data_len = -1, int padding = RSA_PKCS1_OAEP_PADDING);

    QString public_decrypt(QString data, int padding = RSA_PKCS1_PADDING);
    QString public_decrypt(std::string data, int padding = RSA_PKCS1_PADDING);
    QString public_decrypt(const char* data, int data_len = -1, int padding = RSA_PKCS1_PADDING);

    QString private_decrypt(QString data, int padding = RSA_PKCS1_OAEP_PADDING);
    QString private_decrypt(std::string data, int padding = RSA_PKCS1_OAEP_PADDING);
    QString private_decrypt(const char* data, int data_len = -1, int padding = RSA_PKCS1_OAEP_PADDING);

    QString private_encrypt(QString data, int padding = RSA_PKCS1_PADDING);
    QString private_encrypt(std::string data, int padding = RSA_PKCS1_PADDING);
    QString private_encrypt(const char* data, int data_len = -1, int padding = RSA_PKCS1_PADDING);
    RSA* getKey();
private:
    char* public_key;
    char* private_key;
    RSA* keypair;

private:
    RSA* CreateRSA(bool isPublic);
};

#endif // RSACRPTO_H
