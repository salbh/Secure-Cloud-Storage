#ifndef SECURE_CLOUD_STORAGE_RENAME_H
#define SECURE_CLOUD_STORAGE_RENAME_H

#include "Config.h"

class Rename {

private:
    uint8_t m_message_code;
    char m_old_filename[Config::FILE_NAME_LEN];
    char m_new_filename[Config::FILE_NAME_LEN];

public:
    Rename();
    Rename(const std::string &old_filename, const std::string &new_filename);
    uint8_t *serializeRenameMessage();
    Rename deserializeRenameMessage(uint8_t *message_buffer);
};

#endif //SECURE_CLOUD_STORAGE_RENAME_H
