#ifndef SECURE_CLOUD_STORAGE_CONFIG_H
#define SECURE_CLOUD_STORAGE_CONFIG_H

#include <cstdint>

class Config {

public:
    static constexpr uint8_t FILE_NAME_LEN = 35;
    static constexpr long MESSAGE_CODE_PACKET_SIZE = 71 * sizeof(uint8_t);
    static constexpr uint8_t USERNAME_LEN = 35;
};

#endif //SECURE_CLOUD_STORAGE_CONFIG_H