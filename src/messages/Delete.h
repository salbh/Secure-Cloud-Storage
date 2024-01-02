#ifndef SECURE_CLOUD_STORAGE_DELETE_H
#define SECURE_CLOUD_STORAGE_DELETE_H

#include <cstdint>
#include <string>
#include "Config.h"

using namespace std;

class Delete {

private:
    uint8_t m_message_code{};
    char m_file_name[Config::FILE_NAME_LEN]{};

public:
    Delete();

    Delete(const string &file_name);

    uint8_t *serialize();

    Delete deserialize(uint8_t *buffer);

    size_t getSize() const;

};


#endif //SECURE_CLOUD_STORAGE_DELETE_H
