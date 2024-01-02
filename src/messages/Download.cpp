#include <string>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include "Download.h"
#include "CodesManager.h"

using namespace std;

/**
 * @brief Default constructor for the Download class.
 */
DownloadM1::DownloadM1() = default;

/**
 * @brief Constructor for creating a Download object for a DOWNLOAD_REQUEST message (Download M1).
 * @param filename The filename associated with the download request.
 */
DownloadM1::DownloadM1(const string& filename) {
    m_message_code = static_cast<uint8_t>(Message::DOWNLOAD_REQUEST);
    strncpy(m_filename, filename.c_str(), Config::FILE_NAME_LEN);
}

/**
 * @brief Serialize the Download M1 message.
 * @return A dynamically allocated buffer containing the serialized message.
 */
uint8_t* DownloadM1::serializeDownloadM1() {
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

/**
 * @brief Deserialize a Download M1 message from a buffer.
 * @param message_buffer The buffer containing the serialized message.
 * @return A Download object representing the deserialized message.
 */
DownloadM1 DownloadM1::deserializeDownloadM1(uint8_t* message_buffer) {
    // Create a Download object to store the deserialized message
    DownloadM1 downloadMessage;

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

/**
 * @brief Constructor for creating a Download object for a DOWNLOAD_ACK message (Download M2).
 * @param file_size The size of the file being acknowledged.
 */
DownloadM2::DownloadM2(const size_t& file_size) {
    // Set the message code to indicate a Download Ack
    m_message_code = static_cast<uint8_t>(Message::DOWNLOAD_ACK);

    m_file_size = static_cast<uint32_t>(file_size);
}

/**
 * @brief Serialize the Download M2 message.
 * @return A dynamically allocated buffer containing the serialized message.
 */
uint8_t* DownloadM2::serializeDownloadM2() {
    // Allocate memory for the message buffer
    uint8_t* message_buffer = new (nothrow) uint8_t[sizeof(uint8_t) + sizeof(uint32_t)];
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

/**
 * @brief Deserialize a Download M2 message from a buffer.
 * @param message_buffer The buffer containing the serialized message.
 * @param file_size The size of the file being acknowledged.
 * @return A Download object representing the deserialized message.
 */
DownloadM2 DownloadM2::deserializeDownloadM2(uint8_t* message_buffer, const size_t& file_size) {
    // Create a DownloadM2 object to store the deserialized message
    DownloadM2 downloadM2(file_size);

    size_t current_buffer_position = 0;

    // Copy the message code from the buffer
    memcpy(&downloadM2.m_message_code, message_buffer, sizeof(uint8_t));
    current_buffer_position += sizeof(uint8_t);
    // Copy the size of the file to be downloaded from the buffer
    memcpy(&downloadM2.m_file_size, message_buffer + current_buffer_position, sizeof(uint32_t));
    // Return the deserialized Download message
    return downloadM2;
}

/**
 * @brief Constructor for creating a Download object for a DOWNLOAD_CHUNK message (Download M3+i).
 * @param file_chunk The file chunk data.
 * @param file_chunk_size The size of the file chunk data.
 */
DownloadMi::DownloadMi(uint8_t* file_chunk, int file_chunk_size) {
    // Set the message code to indicate a Download Chunk
    m_message_code = static_cast<uint8_t>(Message::DOWNLOAD_CHUNK);
    m_file_chunk = new uint8_t[file_chunk_size];
    memcpy(m_file_chunk, file_chunk, file_chunk_size * sizeof(uint8_t));
}

/**
 * @brief Constructor for creating a Download object for a DOWNLOAD_CHUNK message (Download M3+i for the deserialize phase).
 * @param file_chunk_size The size of the file chunk data.
 */
DownloadMi::DownloadMi(int file_chunk_size) {
    // Set the message code to indicate a Download Chunk
    m_message_code = static_cast<uint8_t>(Message::DOWNLOAD_CHUNK);
    m_file_chunk = new uint8_t[file_chunk_size];
}

/**
 * @brief Destructor for the DownloadMi class.
 * Releases the dynamically allocated memory for file_chunk.
 */
DownloadMi::~DownloadMi() {
    delete[] m_file_chunk;
}

/**
 * @brief Serialize the Download M3+i message.
 * @param file_chunk_size The size of the file chunk data.
 * @return A dynamically allocated buffer containing the serialized message.
 */
uint8_t* DownloadMi::serializeDownloadMi(int file_chunk_size) {
    // Allocate memory for the message buffer
    uint8_t* message_buffer = new (nothrow) uint8_t[sizeof(uint8_t) + file_chunk_size * sizeof(uint8_t)];
    // Check if memory allocation was successful
    if (!message_buffer) {
        cerr << "Download - Error during the serialization: Failed to allocate memory!" << endl;
        return nullptr;
    }

    size_t current_buffer_position = 0;
    // Copy the message code into the buffer
    memcpy(message_buffer, &m_message_code, sizeof(uint8_t));
    current_buffer_position += sizeof(uint8_t);
    // Copy the file chunk into the buffer
    memcpy(message_buffer + current_buffer_position, m_file_chunk, file_chunk_size * sizeof(uint8_t));
    // Return the serialized message buffer
    return message_buffer;
}

/**
 * @brief Deserialize a Download M3+i message from a buffer.
 * @param message_buffer The buffer containing the serialized message.
 * @param file_chunk_size The size of the file chunk data.
 * @return A Download object representing the deserialized message.
 */
DownloadMi DownloadMi::deserializeDownloadMi(uint8_t* message_buffer, int file_chunk_size) {
    // Create a Download object to store the deserialized message
    DownloadMi downloadMi(file_chunk_size);

    size_t current_buffer_position = 0;
    // Copy the message code from the buffer
    memcpy(&downloadMi.m_message_code, message_buffer, sizeof(uint8_t));
    current_buffer_position += sizeof(uint8_t);
    // Copy the new file chunk from the buffer
    memcpy(downloadMi.m_file_chunk, message_buffer + current_buffer_position, file_chunk_size * sizeof(uint8_t));
    // Return the deserialized Download message
    return downloadMi;
}