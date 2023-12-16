#ifndef SECURE_CLOUD_STORAGE_LOGOUT_H
#define SECURE_CLOUD_STORAGE_LOGOUT_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#define MESSAGE_CODE_PACKET_SIZE 65 * sizeof(uint8_t) //to move in a config file and check the correct size

using namespace std;


class Logout {
    uint8_t m_message_code;
    uint32_t m_counter;

    Logout();
    Logout(uint32_t counter);

    uint8_t *serializeLogoutMessage();
    Logout deserializeLogoutMessage(uint8_t *buffer);
};




#endif //SECURE_CLOUD_STORAGE_LOGOUT_H
