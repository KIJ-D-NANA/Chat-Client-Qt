#ifndef SHA1HASH_H
#define SHA1HASH_H
#include <QString>
#include <string>
#include <stdlib.h>

class SHA1Hash
{
public:
    SHA1Hash();
    ~SHA1Hash();
    bool checkIntegrity(QString raw, QString hash);
    bool checkIntegrity(std::string raw, std::string hash);
    bool checkIntegrity(size_t input_len, unsigned char* raw, const char *hash_string);
    QString toSHA1(QString data);
    QString toSHA1(std::string data);
    QString toSHA1(const char* data, size_t data_len);
};

#endif // SHA1HASH_H
