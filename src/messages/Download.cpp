#include <string>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include "Download.h"
#include "CodesManager.h"

using namespace std;

Download::Download() = default;

// Download M1
Download::Download(const string& filename) {
    m_message_code = static_cast<uint8_t>(Message::DOWNLOAD_REQUEST);

    strncpy(m_filename, filename.c_str(), Config::FILE_NAME_LEN);
}

uint8_t* Download::serializeDownloadM1() {
    // Allocate memory for the message buffer
    uint8_t* message_buffer = new (nothrow) uint8_t[Config::MESSAGE_CODE_PACKET_SIZE];
    // Check if memory allocation was successful
    if (!message_buffer) {
        cerr << "Download - Error during the serialization: Failed to allocate memory!" << endl;
        return nullptr;
    }
    size_t current_buffer_position = 0;
    // Copy the message code into the buffer
    memcpy(message_buffer, &m_message_code, sizeof(uint8_t));
    current_buffer_position += sizeof(uint8_t);
    // Copy the filename into the buffer
    memcpy(message_buffer + current_buffer_position, &m_filename, Config::FILE_NAME_LEN * sizeof(char));
    current_buffer_position += Config::FILE_NAME_LEN * sizeof(char);
    // Generate random bytes to fill the remaining space in the buffer
    if (RAND_bytes(message_buffer + current_buffer_position,
                   Config::MESSAGE_CODE_PACKET_SIZE - current_buffer_position) != 1) {
        cerr << "Download - Error during serialization: RAND_bytes failed!" << endl;
        delete[] message_buffer; // Release memory in case of failure
        return nullptr;
    }
    // Return the serialized message buffer
    return message_buffer;
}

Download Download::deserializeDownloadM1(uint8_t* message_buffer) {
    // Create a Download object to store the deserialized message
    Download downloadMessage;

    size_t current_buffer_position = 0;

    // Copy the message code from the buffer
    memcpy(&downloadMessage.m_message_code, message_buffer, sizeof(uint8_t));
    current_buffer_position += sizeof(uint8_t);
    // Copy the filename from the buffer
    memcpy(&downloadMessage.m_filename, message_buffer + current_buffer_position,
           Config::FILE_NAME_LEN * sizeof(char));
    // Return the deserialized Download message
    return downloadMessage;
}

// Download M2
Download::Download(const size_t& file_size) {
    // Set the message code to indicate a Download Ack
    m_message_code = static_cast<uint8_t>(Message::DOWNLOAD_ACK);

    m_file_size = static_cast<uint32_t>(file_size);
}

uint8_t* Download::serializeDownloadM2() {
    // Allocate memory for the message buffer
    uint8_t*  message_buffer = new (nothrow) uint8_t[sizeof(uint8_t) + sizeof(uint32_t)];
    // Check if memory allocation was successful
    if (!message_buffer) {
        cerr << "Download - Error during the serialization: Failed to allocate memory!" << endl;
        return nullptr;
    }

    size_t current_buffer_position = 0;
    // Copy the message code into the buffer
    memcpy(message_buffer, &m_message_code, sizeof(uint8_t));
    current_buffer_position += sizeof(uint8_t);
    // Copy the size of the file to be downloaded into the buffer
    memcpy(message_buffer + current_buffer_position, &m_file_size, sizeof(uint32_t));
    // Return the serialized message buffer
    return message_buffer;
}

Download Download::deserializeDownloadM2(uint8_t* message_buffer, const size_t& file_size) {
    // Create a DownloadM2 object to store the deserialized message
    Download downloadM2(file_size);

    size_t current_buffer_position = 0;

    // Copy the message code from the buffer
    memcpy(&downloadM2.m_message_code, message_buffer, sizeof(uint8_t));
    current_buffer_position += sizeof(uint8_t);
    // Copy the size of the file to be downloaded from the buffer
    memcpy(&downloadM2.m_file_size, message_buffer + current_buffer_position, sizeof(uint32_t));
    // Return the deserialized Rename message
    return downloadM2;
}

// Downlaod M3+i
