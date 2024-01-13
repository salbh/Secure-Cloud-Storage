#ifndef SECURE_CLOUD_STORAGE_SIMPLEMESSAGE_H
#define SECURE_CLOUD_STORAGE_SIMPLEMESSAGE_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>


using namespace std;


class SimpleMessage {
private:
    uint8_t m_message_code;

public:
    SimpleMessage();

    SimpleMessage(uint8_t message_code);

    uint8_t *serialize();

    static SimpleMessage deserialize(uint8_t *message_buffer);

    static size_t getSize();

    uint8_t getMessageCode() const;
};


#endif //SECURE_CLOUD_STORAGE_SIMPLEMESSAGE_H
