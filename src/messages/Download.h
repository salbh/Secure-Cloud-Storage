#ifndef SECURE_CLOUD_STORAGE_DOWNLOAD_H
#define SECURE_CLOUD_STORAGE_DOWNLOAD_H

#include "Config.h"

using namespace std;

class Download {

private:

    int m_message_code;
    char m_filename[Config::FILE_NAME_LEN];
    uint32_t m_file_size;

public:
    Download();

    // M1:(DOWNLOAD REQUEST, FILENAME)
    Download(const string &filename);
    uint8_t *serializeDownloadM1();
    Download deserializeDownloadM1(uint8_t *message_buffer);

    //M2:(DOWNLOAD ACK, FILESIZE)
    Download(const size_t &file_size);
    uint8_t *serializeDownloadM2();
    Download deserializeDownloadM2(uint8_t *message_buffer, const size_t &file_size);
    //M3+i:(DOWNLOAD RESPONSE,FILE CHUNK)
};


#endif //SECURE_CLOUD_STORAGE_DOWNLOAD_H
