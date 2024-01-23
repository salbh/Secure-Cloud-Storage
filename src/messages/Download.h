#ifndef SECURE_CLOUD_STORAGE_DOWNLOAD_H
#define SECURE_CLOUD_STORAGE_DOWNLOAD_H

#include "Config.h"
#include <string>
#include <cstdint>

using namespace std;

class DownloadM1 {
private:
    uint8_t m_message_code{};
    char m_filename[Config::FILE_NAME_LEN]{};

public:
    DownloadM1();
    explicit DownloadM1(const string& filename);

    uint8_t* serialize();
    static DownloadM1 deserialize(uint8_t* message_buffer);
    static size_t getMessageSize();
    const char *getFilename() const;
};

class DownloadM2 {
private:
    uint8_t m_message_code{};
    uint32_t m_file_size{};

public:
    DownloadM2();
    DownloadM2(uint8_t message_code, const size_t &file_size);

    uint8_t* serialize();
    static DownloadM2 deserialize(uint8_t* message_buffer);
    static size_t getMessageSize();
    uint8_t getMessageCode() const;
    uint32_t getFileSize() const;
};

class DownloadMi {
private:
    uint8_t m_message_code;
    uint8_t* m_file_chunk;

public:
    DownloadMi(uint8_t* file_chunk, size_t chunk_size);
    explicit DownloadMi(size_t chunk_size);
    ~DownloadMi();

    uint8_t *serialize(size_t chunk_size);
    static DownloadMi deserialize(uint8_t* message_buffer, size_t chunk_size);
    static size_t getMessageSize(size_t chunk_size);
    uint8_t getMessageCode() const;
    uint8_t *getFileChunk() const;
};

#endif // SECURE_CLOUD_STORAGE_DOWNLOAD_H

