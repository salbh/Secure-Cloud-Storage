#include "Delete.h"
#include "CodesManager.h"
#include <string>
#include <cstring>
#include <openssl/rand.h>

using namespace std;

Delete::Delete() = default;

Delete::Delete(const string& file_name) {
    m_message_code = static_cast<uint8_t>(Message::DELETE_REQUEST);
    strncpy(m_file_name, file_name.c_str(), FILE_NAME_LEN);
}

uint8_t* Delete::serializeDeleteMessage() {
    uint8_t* buffer = new uint8_t[MESSAGE_CODE_PACKET_SIZE];

    size_t position = 0;
    memcpy(buffer, &m_message_code, sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(buffer + position, &m_file_name, FILE_NAME_LEN * sizeof(char));
    position += FILE_NAME_LEN * sizeof(char);

    RAND_bytes(buffer + position, MESSAGE_CODE_PACKET_SIZE - position);

    return buffer;
}

Delete Delete::deserializeDeleteMessage(uint8_t* buffer) {
    Delete deleteMessage;

    size_t position = 0;
    memcpy(&deleteMessage.m_message_code, buffer, sizeof(uint8_t));
    position += sizeof(uint8_t);

    memcpy(&deleteMessage.m_file_name, buffer + position, FILE_NAME_LEN * sizeof(char));

    return deleteMessage;
}






