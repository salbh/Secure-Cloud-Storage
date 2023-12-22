#ifndef SECURE_CLOUD_STORAGE_LIST_H
#define SECURE_CLOUD_STORAGE_LIST_H

#include <cstdint>
#include <vector>
#include <string>

//M1:(LIST_REQUEST) --> is a SimpleMessage, not defined here but initialized in the Client
//M2:(LIST_SIZE, LIST SIZE)
//M3:(LIST_RESPONSE, FILE LIST)

// ListM2 class represents the second message for list request
class ListM2 {
public:
    ListM2();
    ListM2(uint32_t listSize);

    uint8_t* serialize();
    ListM2 deserialize(uint8_t* buffer);
    size_t getSize() const;

private:
    uint8_t m_message_code{};
    uint32_t m_list_size{};
};

// ListM3 class represents the third message for list response
class ListM3 {

public:
    ListM3();
    ListM3(uint32_t list_size, uint8_t* file_list);

    uint8_t* serialize();
    ListM3 deserialize(uint8_t* buffer, int buffer_len);
    size_t getSize() const;

    virtual ~ListM3();

private:
    uint8_t m_message_code{};
    uint32_t m_list_size{};
    uint8_t* m_file_list{};
};

#endif //SECURE_CLOUD_STORAGE_LIST_H

