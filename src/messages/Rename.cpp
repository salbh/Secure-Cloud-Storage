#include <string>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include "Rename.h"
#include "CodesManager.h"

using namespace std;

/**
 * @brief Default constructor for the Rename class.
 */
Rename::Rename() = default;

/**
 * @brief Parameterized constructor for the Rename class.
 * @param old_filename The original filename before renaming.
 * @param new_filename The new filename after renaming.
 */
Rename::Rename(const string& old_filename, const string& new_filename) {
    // Set the message code to indicate a rename request
    m_message_code = static_cast<uint8_t>(Message::RENAME_REQUEST);

    // Copy old and new filenames into member variables, ensuring a fixed length
    strncpy(m_old_filename, old_filename.c_str(), Config::FILE_NAME_LEN);
    strncpy(m_new_filename, new_filename.c_str(), Config::FILE_NAME_LEN);
}

/**
 * @brief Serializes the Rename message into a byte buffer.
 * @return A pointer to the serialized message buffer.
 * @note The caller is responsible for freeing the allocated memory.
 */
uint8_t* Rename::serializeRenameMessage() {
    // Allocate memory for the message buffer
    uint8_t* message_buffer = new (nothrow) uint8_t[Config::MAX_PACKET_SIZE];
    // Check if memory allocation was successful
    if (!message_buffer) {
        cerr << "Rename - Error during the serialization: Failed to allocate memory!" << endl;
        return nullptr;
    }

    size_t current_buffer_position = 0;
    // Copy the message code into the buffer
    memcpy(message_buffer, &m_message_code, sizeof(uint8_t));
    current_buffer_position += sizeof(uint8_t);
    // Copy the old filename into the buffer
    memcpy(message_buffer + current_buffer_position, &m_old_filename, Config::FILE_NAME_LEN * sizeof(char));
    current_buffer_position += Config::FILE_NAME_LEN * sizeof(char);
    // Copy the new filename into the buffer
    memcpy(message_buffer + current_buffer_position, &m_new_filename, Config::FILE_NAME_LEN * sizeof(char));
    current_buffer_position += Config::FILE_NAME_LEN * sizeof(char);
    // Generate random bytes to fill the remaining space in the buffer
    if (RAND_bytes(message_buffer + current_buffer_position,
                   Config::MAX_PACKET_SIZE - current_buffer_position) != 1) {
        cerr << "Rename - Error during serialization: RAND_bytes failed!" << endl;
        delete[] message_buffer; // Release memory in case of failure
        return nullptr;
    }
    // Return the serialized message buffer
    return message_buffer;
}

/**
 * @brief Deserializes a byte buffer into a Rename message.
 * @param message_buffer The byte buffer containing the serialized message.
 * @return A Rename object representing the deserialized message.
 */
Rename Rename::deserializeRenameMessage(uint8_t* message_buffer) {
    // Create a Rename object to store the deserialized message
    Rename renameMessage;

    size_t current_buffer_position = 0;

    // Copy the message code from the buffer
    memcpy(&renameMessage.m_message_code, message_buffer, sizeof(uint8_t));
    current_buffer_position += sizeof(uint8_t);
    // Copy the old filename from the buffer
    memcpy(&renameMessage.m_old_filename, message_buffer + current_buffer_position,
           Config::FILE_NAME_LEN * sizeof(char));
    current_buffer_position += Config::FILE_NAME_LEN * sizeof(char);
    // Copy the new filename from the buffer
    memcpy(&renameMessage.m_new_filename, message_buffer + current_buffer_position,
           Config::FILE_NAME_LEN * sizeof(char));
    // Return the deserialized Rename message
    return renameMessage;
}
