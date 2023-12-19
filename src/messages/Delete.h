#ifndef SECURE_CLOUD_STORAGE_DELETE_H
#define SECURE_CLOUD_STORAGE_DELETE_H

#include <cstdint>
#include <string>

using namespace std;

class Delete {

public:
    Delete();
    Delete(const string& file_name);

    static constexpr long MESSAGE_CODE_PACKET_SIZE = 65 * sizeof(uint8_t);
    static constexpr uint8_t FILE_NAME_LEN = 35;

    uint8_t *serializeDeleteMessage();
    Delete deserializeDeleteMessage(uint8_t *buffer);

private:
    uint8_t m_message_code;
    char m_file_name[FILE_NAME_LEN];
};


#endif //SECURE_CLOUD_STORAGE_DELETE_H
