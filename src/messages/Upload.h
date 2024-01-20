#ifndef SECURE_CLOUD_STORAGE_UPLOAD_H
#define SECURE_CLOUD_STORAGE_UPLOAD_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "CodesManager.h"
#include "Config.h"


//M1:(UPLOAD REQUEST, FILENAME SIZE)
//M2:(SUCCESS ACK for the request) --> is SimpleMessage (initialized in the server) and not defined here
//M3+i:(UPLOAD CHUNK, FILE CHUNK)
//M3+i+1:(SUCCESS ACK for the upload) --> is SimpleMessage (initialized in the server) and not defined here


class UploadM1 {

private:
    uint8_t m_message_code;
    char m_filename[Config::FILE_NAME_LEN];
    uint32_t m_file_size;

public:
    UploadM1();
    UploadM1(std::string& file_name, size_t file_size);

    uint8_t* serializeUploadM1();
    static UploadM1 deserializeUploadM1(uint8_t* upload_message_buffer);
    static size_t getSizeUploadM1();
    const char *getFilename() const;
    uint32_t getFileSize() const;

};



class UploadMi {
private:
    uint8_t m_message_code;
    uint8_t* m_chunk;
    int m_chunk_size;

public:
    UploadMi();
    UploadMi(uint8_t* chunk, int chunk_size);
    ~UploadMi();

    uint8_t* serializeUploadMi();
    static UploadMi deserializeUploadMi(uint8_t* upload_message_buffer, int chunk_size);
    static size_t getSizeUploadMi(int chunk_size);
    uint8_t *getChunk() const;

};



#endif //SECURE_CLOUD_STORAGE_UPLOAD_H
