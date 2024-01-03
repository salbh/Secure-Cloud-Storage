#ifndef SECURE_CLOUD_STORAGE_AUTHENTICATION_H
#define SECURE_CLOUD_STORAGE_AUTHENTICATION_H

#include <cstdint>
#include <string>
#include "Config.h"

using namespace std;

namespace {
    const uint16_t EPHEMERAL_KEY_LEN = 1024;
}

class AuthenticationM1 {
private:
    uint8_t m_ephemeral_key[EPHEMERAL_KEY_LEN];
    uint32_t m_ephemeral_key_size;
    char m_username[Config::USERNAME_LEN];

public:
    AuthenticationM1();
    AuthenticationM1(uint8_t* ephemeral_key, int ephemeral_key_size, const string& username);

    int getMessageSize();

    uint8_t* serializeAuthenticationM1();
    AuthenticationM1 deserializeAuthenticationM1(uint8_t* message_buffer);
};


#endif //SECURE_CLOUD_STORAGE_AUTHENTICATION_H