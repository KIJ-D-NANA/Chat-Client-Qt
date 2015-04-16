#include "sha1hash.h"
#include <openssl/sha.h>

SHA1Hash::SHA1Hash()
{

}

SHA1Hash::~SHA1Hash()
{

}

bool SHA1Hash::checkIntegrity(QString raw, QString hash){
//    char raw_cstr[raw.length()];
    QByteArray ba = raw.toLatin1();
    char* temp = ba.data();
    QByteArray ba2 = hash.toLatin1();
    char* temp2 = ba2.data();
    return this->checkIntegrity(raw.length(), (unsigned char*)temp, temp2);
}

bool SHA1Hash::checkIntegrity(size_t input_len, unsigned char *raw, char *hash_string){
    char hash_out[SHA_DIGEST_LENGTH + 1];
    char hash_value[SHA_DIGEST_LENGTH * 2 + 1];
    SHA1(raw, input_len, (unsigned char*)hash_out);
    for(int i = 0; i < SHA_DIGEST_LENGTH; i++){
        sprintf(&hash_value[i * 2], "%02x", (unsigned int)hash_out[i]);
    }
    return strcmp(hash_value, hash_string) == 0 ? true : false;
}

bool SHA1Hash::checkIntegrity(std::string raw, std::string hash){
    return this->checkIntegrity(raw.length(), raw.c_str(), hash.c_str());
}

QString SHA1Hash::toSHA1(QString data){
    QByteArray ba = data.toLatin1();
    return this->toSHA1(ba.data(), data.length());
}

QString SHA1Hash::toSHA1(string data){
    return this->toSHA1(data.c_str(), data.size());
}

QString SHA1Hash::toSHA1(const char *data, size_t data_len){
    char hash_out[SHA_DIGEST_LENGTH + 1];
    char hash_value[SHA_DIGEST_LENGTH * 2 + 1];
    SHA1((unsigned char*)data, data_len, (unsigned char*)hash_out);
    for(int i = 0; i < SHA_DIGEST_LENGTH; i++){
        sprintf(&hash_value[i * 2], "%02x", (unsigned int)hash_out[i]);
    }
    return QString::fromUtf8(hash_value);
}
