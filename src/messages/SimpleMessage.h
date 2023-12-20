#ifndef SECURE_CLOUD_STORAGE_SIMPLEMESSAGE_H
#define SECURE_CLOUD_STORAGE_SIMPLEMESSAGE_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#define MESSAGE_CODE_PACKET_SIZE 71 * sizeof(uint8_t) //to move in a config file and check the correct size

using namespace std;


class SimpleMessage {
    uint8_t m_message_code;

    SimpleMessage();
    SimpleMessage(int message_code);

    uint8_t *serializeSimpleMessage();
    SimpleMessage deserializeSimpleMessage(uint8_t *message_buffer);
};




#endif //SECURE_CLOUD_STORAGE_SIMPLEMESSAGE_H
