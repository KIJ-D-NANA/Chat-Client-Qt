#include "rsacrpto.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <string.h>
#include <QDebug>

RSACrpto::RSACrpto()
{
    this->public_key = NULL;
    this->private_key = NULL;
    this->keypair = NULL;
}

RSACrpto::~RSACrpto()
{
    free(public_key);
    free(private_key);
    if(keypair != NULL)
        RSA_free(keypair);
}

RSA* RSACrpto::InitKey(size_t key_len){
    size_t pri_len;
    size_t pub_len;

    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4);
    keypair = RSA_new();
    RSA_generate_key_ex(keypair, key_len, bne, NULL);
    BN_free(bne);

    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0 ,NULL, NULL);
    PEM_write_bio_RSA_PUBKEY(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    private_key = (char*)malloc(pri_len + 1);
    public_key = (char*)malloc(pub_len + 1);

    BIO_read(pri, private_key, pri_len);
    BIO_read(pub, public_key, pub_len);

    private_key[pri_len] = '\0';
    public_key[pub_len] = '\0';

    BIO_free_all(pri);
    BIO_free_all(pub);

    return keypair;
}

RSA* RSACrpto::CreateRSA(bool isPublic){
    BIO* keybio;
    if(isPublic){
        keybio = BIO_new_mem_buf(this->public_key, -1);
        if(keybio == NULL)
            return 0;
        keypair = PEM_read_bio_RSA_PUBKEY(keybio, &keypair, NULL, NULL);
        if(keypair == NULL){
            keypair = PEM_read_bio_RSAPublicKey(keybio, &keypair, NULL, NULL);
        }
    }
    else{
        keybio = BIO_new_mem_buf(this->private_key, -1);
        if(keybio == NULL)
            return 0;
        keypair = PEM_read_bio_RSAPrivateKey(keybio, &keypair, NULL, NULL);
    }
    if(keypair == NULL){
        char* err = (char*)malloc(130);
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        printf("ERROR: %s\n", err);
        free(err);
    }
    BIO_free(keybio);
    return keypair;
}

bool RSACrpto::setPubKey(const char *public_key, int public_len){
    if(this->public_key != NULL)
        free(this->public_key);
    this->public_key = NULL;
    int length;
    if(public_len == -1){
        length = strlen(public_key);
        this->public_key = (char*)malloc(length);
    }
    else{
        length = public_len;
        this->public_key = (char*)malloc(public_len);
    }

    if(this->public_key){
        memcpy(this->public_key, public_key, length);
        this->public_key[length] = '\0';
        this->CreateRSA(true);
        return true;
    }
    else{
        return false;
    }
}

bool RSACrpto::setPubKey(FILE *public_key){
    fseek(public_key, 0, SEEK_END);
    size_t file_size = ftell(public_key);

    if(this->public_key != NULL)
        free(this->public_key);
    this->public_key = NULL;
    this->public_key = (char*)malloc(file_size);
    if(!this->public_key)
        return false;

    fseek(public_key, 0, SEEK_SET);
    fread(this->public_key, 1, file_size, public_key);
    this->CreateRSA(true);
    return true;
}

bool RSACrpto::setPubKey(QString public_key){
    QByteArray ba = public_key.toLatin1();
    return this->setPubKey(ba.data(), public_key.length());
}

bool RSACrpto::setPubKey(std::string public_key){
    return this->setPubKey(public_key.c_str(), public_key.length());
}

bool RSACrpto::setPrivateKey(const char *private_key, int private_len){
    if(this->private_key != NULL)
        free(this->private_key);
    this->private_key = NULL;
    int length;
    if(private_len == -1){
        length = strlen(private_key);
        this->private_key = (char*)malloc(length);
    }
    else{
        length = private_len;
        this->private_key = (char*)malloc(private_len);
    }

    if(this->private_key){
        memcpy(this->private_key, private_key, length);
        this->CreateRSA(false);
        return true;
    }
    else{
        return false;
    }
}

bool RSACrpto::setPrivateKey(FILE *private_key){
    fseek(private_key, 0, SEEK_END);
    size_t file_size = ftell(private_key);

    if(this->private_key != NULL)
        free(this->private_key);
    this->private_key = NULL;
    this->private_key = (char*)malloc(file_size);
    if(!this->private_key)
        return false;

    fseek(private_key, 0, SEEK_SET);
    fread(this->private_key, 1, file_size, private_key);
    this->CreateRSA(false);
    return true;
}

bool RSACrpto::setPrivateKey(QString private_key){
    QByteArray ba = private_key.toLatin1();
    return this->setPrivateKey(ba.data());
}

bool RSACrpto::setPrivateKey(std::string private_key){
    return this->setPrivateKey(private_key.c_str());
}

int RSACrpto::public_encrypt(const char *data, int data_len, char** output, int padding){
    int data_size;
    if(data_len == -1)
        data_size = strlen(data);
    else
        data_size = data_len;
    if(this->keypair == NULL)
        keypair = this->CreateRSA(true);
    qDebug() << QString::fromUtf8(public_key);
    char *encrypted = (char*)malloc(RSA_size(keypair) + 1);
    int encrypt_len = RSA_public_encrypt(data_size, (unsigned char*)data, (unsigned char*)encrypted, keypair, padding);
    *output = encrypted;
    return encrypt_len;
}

int RSACrpto::public_decrypt(const char *data, int data_len, char** output, int padding){
    int data_size;
    if(data_len == -1)
        data_size = strlen(data);
    else
        data_size = data_len;
    if(this->keypair == NULL)
        keypair = this->CreateRSA(true);
    char *decrypted = (char*)malloc(RSA_size(keypair) + 1);
    int decrypt_len = RSA_public_decrypt(data_size, (unsigned char*)data, (unsigned char*)decrypted, keypair, padding);
    *output = decrypted;
    return decrypt_len;
}

int RSACrpto::private_encrypt(const char *data, int data_len, char** output, int padding){
    int data_size;
    if(data_len == -1)
        data_size = strlen(data);
    else
        data_size = data_len;
    if(this->keypair == NULL)
        keypair = this->CreateRSA(false);
    char *encrypted = (char*)malloc(RSA_size(keypair) + 1);
    int encrypt_len = RSA_private_encrypt(data_size, (unsigned char*)data, (unsigned char*)encrypted, keypair, padding);
    *output = encrypted;
    return encrypt_len;
}

int RSACrpto::private_decrypt(const char *data, int data_len, char** output, int padding){
    int data_size;
    if(data_len == -1)
        data_size = strlen(data);
    else
        data_size = data_len;
    if(this->keypair == NULL)
        keypair = this->CreateRSA(false);
    char *decrypted = (char*)malloc(RSA_size(keypair) + 1);
    int decrypt_len = RSA_private_decrypt(data_size, (unsigned char*)data, (unsigned char*)decrypted, keypair, padding);
    *output = decrypted;
    return decrypt_len;
}

int RSACrpto::public_encrypt(QString data, char** output, int padding){
    QByteArray ba = data.toLatin1();
    return this->public_encrypt(ba.data(), data.length(), output, padding);
}

int RSACrpto::public_encrypt(std::string data, char** output, int padding){
    return this->public_encrypt(data.c_str(), data.length(), output, padding);
}

int RSACrpto::public_decrypt(QString data, char** output, int padding){
    QByteArray ba = data.toLatin1();
    return this->public_decrypt(ba.data(), data.length(), output, padding);
}

int RSACrpto::public_decrypt(std::string data, char** output, int padding){
    return this->public_decrypt(data.c_str(), data.length(), output, padding);
}

int RSACrpto::private_encrypt(QString data, char** output, int padding){
    QByteArray ba = data.toLatin1();
    return this->private_encrypt(ba.data(), data.length(), output, padding);
}

int RSACrpto::private_encrypt(std::string data, char** output, int padding){
    return this->private_encrypt(data.c_str(), data.length(), output, padding);
}

int RSACrpto::private_decrypt(QString data, char** output, int padding){
    QByteArray ba = data.toLatin1();
    return this->private_decrypt(ba.data(), data.length(), output, padding);
}

int RSACrpto::private_decrypt(std::string data, char** output, int padding){
    return this->private_decrypt(data.c_str(), data.length(), output, padding);
}

RSA* RSACrpto::getKey(){
    return this->keypair;
}

QString RSACrpto::getPubKey(){
    return QString::fromUtf8(public_key);
}

QString RSACrpto::getPrivateKey(){
    return QString::fromUtf8(private_key);
}
