#ifndef SECURE_CLOUD_STORAGE_LIST_H
#define SECURE_CLOUD_STORAGE_LIST_H

#include <cstdint>
#include <vector>
#include <string>

//M1:(LIST_REQUEST) --> is a SimpleMessage, not defined here but initialized in the Client
//M2:(LIST_ACK, LIST SIZE)
//M3:(LIST_RESPONSE, FILE LIST)

// ListM2 class represents the second message for the list operation
class ListM2 {

private:
    uint8_t m_message_code{};
    uint32_t m_list_size{};

public:
    ListM2();

    ListM2(uint32_t list_size);

    uint8_t *serialize();

    static ListM2 deserialize(uint8_t *buffer);

    static size_t getMessageSize();

    uint8_t getMessageCode() const;

    uint32_t getListSize() const;
};

// ListM3 class represents the third message for the list operation
class ListM3 {

private:
    uint8_t m_message_code{};
    uint8_t *m_file_list{};

public:
    ListM3();

    ~ListM3();

    ListM3(uint32_t list_size, uint8_t *file_list);

    uint8_t *serialize(uint32_t list_size);

    static ListM3 deserialize(uint8_t *buffer, uint32_t list_size);

    static size_t getMessageSize(uint32_t list_size);

    uint8_t getMessageCode() const;

    uint8_t *getFileList() const;


};

#endif //SECURE_CLOUD_STORAGE_LIST_H

