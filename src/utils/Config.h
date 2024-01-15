#ifndef SECURE_CLOUD_STORAGE_CONFIG_H
#define SECURE_CLOUD_STORAGE_CONFIG_H

#include <cstdint>
#include <openssl/evp.h>

class Config {

public:
    static constexpr uint8_t FILE_NAME_LEN = 35;
    static constexpr uint8_t USERNAME_LEN = 35;
    // Longest packet (excluding chunks)
    // Rename request: 35 B old filename + 35 B new filename + 1 B message code)
    static constexpr long MAX_PACKET_SIZE = 71 * sizeof(uint8_t);
    static constexpr unsigned int AES_TAG_LEN = 16;
    static constexpr unsigned int AES_KEY_LEN = 16;
    static constexpr unsigned int AAD_LEN = 4;
    static constexpr unsigned int IV_LEN = 12;
    static constexpr long CHUNK_SIZE = 1024 * 1024; // 1 MB chunk size in bytes

};

#endif //SECURE_CLOUD_STORAGE_CONFIG_H