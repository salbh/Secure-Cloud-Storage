#include "Delete.h"
#include "CodesManager.h"
#include <string>
#include <cstring>
#include <openssl/rand.h>
#include <iostream>

using namespace std;

/**
* Default constructor for Delete class
*/
Delete::Delete() = default;

/**
 * Constructor for Delete class with a specified file name
 * @param file_name The name of the file to delete
 */
Delete::Delete(const string& file_name) {
    // Set the message code to indicate a delete request
    m_message_code = static_cast<uint8_t>(Message::DELETE_REQUEST);

    // Copy the file name into the class member
    strncpy(m_file_name, file_name.c_str(), Config::FILE_NAME_LEN);
}

/**
 * Serialize the Delete message into a byte buffer
 * @return A dynamically allocated byte buffer containing the serialized message
 */
uint8_t* Delete::serialize() {
    // Allocate memory for the byte buffer
    uint8_t* buffer = new (nothrow) uint8_t[Config::MAX_PACKET_SIZE];
    if (!buffer) {
        cerr << "Delete - Error during serialization: Failed to allocate memory" << endl;
        return nullptr;
    }

    // Serialize the message code
    size_t position = 0;
    memcpy(buffer, &m_message_code, sizeof(m_message_code));
    position += sizeof(m_message_code);

    // Serialize the file name
    memcpy(buffer + position, &m_file_name, Config::FILE_NAME_LEN * sizeof(char));
    position += Config::FILE_NAME_LEN * sizeof(char);

    // Add randomness to the buffer using RAND_bytes
    if (RAND_bytes(buffer + position, Config::MAX_PACKET_SIZE - position) != 1) {
        cerr << "Delete - Error during serialization: RAND_bytes failed" << endl;
        delete[] buffer; // Release memory in case of failure
        return nullptr;
    }

    return buffer;
}

/**
 * Deserialize a byte buffer into a Delete message
 * @param buffer The byte buffer to deserialize
 * @return A Delete object with the deserialized data
 */
Delete Delete::deserialize(uint8_t* buffer) {
    // Create a Delete object for deserialization
    Delete deleteMessage;

    // Deserialize the message code
    size_t position = 0;
    memcpy(&deleteMessage.m_message_code, buffer, sizeof(m_message_code));
    position += sizeof(uint8_t);

    // Deserialize the file name
    memcpy(&deleteMessage.m_file_name, buffer + position, Config::FILE_NAME_LEN * sizeof(char));

    return deleteMessage;
}

/**
 * Get the size of the Delete message in bytes
 * @return The size of the Delete message
 */
size_t Delete::getSize() const {
    return sizeof(m_message_code) +
            sizeof(char) * Config::FILE_NAME_LEN;
}








