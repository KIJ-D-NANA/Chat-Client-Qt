#include "rsaalgorithm.h"
#include <QDebug>
#include <QObject>
RSAAlgorithm::RSAAlgorithm()
{
    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

    pri = BIO_new(BIO_s_mem());
    pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = (char*)malloc(pri_len + 1);
    pub_key = (char*)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    qDebug() << pri_key;
    qDebug() << pub_key;
}
char* RSAAlgorithm::getPublicKey(){
    return pub_key;
}
/*void Encrypt(){
    encrypt = malloc(RSA_size(keypair));
        int encrypt_len;
        err = malloc(130);
        if((encrypt_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt,
                                             keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
            ERR_load_crypto_strings();
            ERR_error_string(ERR_get_error(), err);
            fprintf(stderr, "Error encrypting message: %s\n", err);
        }

}*/
void RSAAlgorithm::setServerKeyPair( char *key, size_t key_len){
//    BIO* bufio;
//    bufio = BIO_new_mem_buf((void*)key, key_len);
//    if(bufio == NULL )qDebug() << "BIO";
    FILE* server = fopen("./public.pem", "r");
    servkey = RSA_new();
    if(PEM_read_RSA_PUBKEY(server, &servkey, NULL, NULL) == NULL){
        qDebug() << "public";
    }
}
void RSAAlgorithm::setPubkeys(QString name,QString key){

        BIO* bufio;
        qDebug() << key;
        bufio = BIO_new_mem_buf((void*)key.toStdString().c_str(), -1);
        pubkeys[name] = RSA_new();
        if(PEM_read_bio_RSA_PUBKEY(bufio, &(pubkeys[name]), NULL, NULL) == NULL){
            qDebug() << "publicshare";
        }
}

RSAAlgorithm::~RSAAlgorithm()
{

}

