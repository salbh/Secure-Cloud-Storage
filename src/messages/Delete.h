#ifndef SECURE_CLOUD_STORAGE_DELETE_H
#define SECURE_CLOUD_STORAGE_DELETE_H

#include <cstdint>
#include <string>
#include "Config.h"

using namespace std;

class Delete {

public:
    Delete();
    Delete(const string& file_name);

    uint8_t *serializeDeleteMessage();
    Delete deserializeDeleteMessage(uint8_t *buffer);

private:
    uint8_t m_message_code;
    char m_file_name[Config::FILE_NAME_LEN];
};


#endif //SECURE_CLOUD_STORAGE_DELETE_H
