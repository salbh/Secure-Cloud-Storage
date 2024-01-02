#ifndef SECURE_CLOUD_STORAGE_DOWNLOAD_H
#define SECURE_CLOUD_STORAGE_DOWNLOAD_H

#include "Config.h"
#include <string>
#include <cstdint>

using namespace std;

class DownloadM1 {
private:
    int m_message_code;
    char m_filename[Config::FILE_NAME_LEN];

public:
    DownloadM1();
    DownloadM1(const string& filename);

    uint8_t* serializeDownloadM1();
    DownloadM1 deserializeDownloadM1(uint8_t* message_buffer);
};

class DownloadM2 {
private:
    int m_message_code;
    uint32_t m_file_size;

public:
    DownloadM2(const size_t& file_size);

    uint8_t* serializeDownloadM2();
    DownloadM2 deserializeDownloadM2(uint8_t* message_buffer, const size_t& file_size);
};

class DownloadMi {
private:
    int m_message_code;
    uint8_t* m_file_chunk;

public:
    DownloadMi(uint8_t* file_chunk, int file_chunk_size);
    DownloadMi(int file_chunk_size);
    ~DownloadMi();

    uint8_t *serializeDownloadMi(int file_chunk_size);
    DownloadMi deserializeDownloadMi(uint8_t* message_buffer, int file_chunk_size);
    size_t getSizeDownloadMi(int file_chunk_size);

};

#endif // SECURE_CLOUD_STORAGE_DOWNLOAD_H

