#include "base64engine.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

int Base64Engine::encode(const unsigned char *buffer, size_t length, char **base64_text){
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    *base64_text = (char*) malloc(sizeof(char) * bufferPtr->length);
    memcpy(*base64_text, bufferPtr->data, sizeof(char) * bufferPtr->length);
    int length2 = bufferPtr->length;

    BIO_free_all(bio);

    return length2;
}

QString Base64Engine::encode(const char *buffer, size_t length){
    char* encoded;
    int encode_length = Base64Engine::encode((unsigned char*)buffer, length, &encoded);
    QString message = QString::fromUtf8(encoded, encode_length);
    free(encoded);
    return message;
}

QString Base64Engine::encode(std::string plain_text){
    return Base64Engine::encode(plain_text.c_str(), plain_text.length());
}

QString Base64Engine::encode(QString plain_text){
    QByteArray ba = plain_text.toLatin1();
    return Base64Engine::encode(ba.data(), plain_text.length());
}

size_t Base64Engine::calcDecodeLength(const char *b64input){
    size_t len = strlen(b64input),
        padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=')
        padding = 2;
    else if (b64input[len-1] == '=')
        padding = 1;

    return (len*3)/4 - padding;
}

int Base64Engine::decode(const char *b64message, unsigned char **buffer, size_t length){
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (uint8_t*)malloc(decodeLen);

    char* copy_message = (char*)malloc(length);
    memcpy(copy_message, b64message, length);

    bio = BIO_new_mem_buf(copy_message, length);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int result = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
    free(copy_message);

    return result; //success
}
