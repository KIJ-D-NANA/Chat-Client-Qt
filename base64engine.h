#ifndef BASE64ENGINE_H
#define BASE64ENGINE_H
#include <stdlib.h>
#include <QString>
#include <string>

namespace Base64Engine
{
    int encode(const unsigned char* buffer, size_t length, char** base64_text);
    int decode(const char* b64message, unsigned char** buffer, size_t length);
    size_t calcDecodeLength(const char* b64input);

    QString encode(const char *buffer, size_t length);
    QString encode(std::string plain_text);
    QString encode(QString plain_text);
}

#endif // BASE64ENGINE_H
