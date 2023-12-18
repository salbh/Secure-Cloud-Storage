#ifndef SECURE_CLOUD_STORAGE_DELETE_H
#define SECURE_CLOUD_STORAGE_DELETE_H


#include <cstdint>

class Delete {
    uint8_t m_message_code;
    uint32_t m_counter;

    Delete();
    Delete(uint32_t counter);

    uint8_t *serializeDeleteMessage();
    Delete deserializeDeleteMessage(uint8_t *buffer);

};


#endif //SECURE_CLOUD_STORAGE_DELETE_H
