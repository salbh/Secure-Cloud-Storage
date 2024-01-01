#ifndef SECURE_CLOUD_STORAGE_CONFIG_H
#define SECURE_CLOUD_STORAGE_CONFIG_H

#include <cstdint>

class Config {

public:
    static constexpr uint8_t FILE_NAME_LEN = 35;
    static constexpr long MESSAGE_CODE_PACKET_SIZE = 71 * sizeof(uint8_t);
    static constexpr long CHUNK_SIZE = 1000 * 1024; // 1 MB chunk size
};

#endif //SECURE_CLOUD_STORAGE_CONFIG_H