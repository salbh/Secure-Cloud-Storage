#include <iostream>
#include <string>
#include <cstring>
#include <openssl/rand.h>

#include "Upload.h"
#include "CodesManager.h"
#include "Config.h"


//-------------------------------------------UPLOAD MESSAGE 1-------------------------------------------//

/**
 * Default constructor of UploadM1 class
 */
UploadM1::UploadM1() = default;


/**
 * Constructor of UploadM1 class object. Used to create a type 1 upload request message (UploadM1).
 * @param file_name a string containing the name of the file to be uploaded.
 * @param file_size a size_t representing the size of the file to be uploaded.
 */
UploadM1::UploadM1(std::string&  filename, size_t file_size) {
    // Set the message code attribute of the current object to UPLOAD_REQ.
    m_message_code = static_cast<uint8_t>(Message::UPLOAD_REQUEST);

    //copy at most FILE_NAME_LEN characters from the file_name string to the m_filename attribute of the current object.
    strncpy(m_filename, filename.c_str(), Config::FILE_NAME_LEN);

    // Set the m_filesize and ensure that does not exceed a maximum value of 4GB (converted in uint32_t), if so is set to 0
    m_file_size = (file_size < 4UL * 1000 * 1000 * 1000) ? (uint32_t)file_size : 0;
}


/**
 * Function to serialize data for the type 1 upload message into a byte buffer
 * @return Returns a dynamically allocated uint8_t array representing the serialized data.
 */
uint8_t *UploadM1::serializeUploadM1() {
    // Dynamically allocate memory for a buffer to hold the serialized data.
    uint8_t* upload_message_buffer = new uint8_t[Config::MAX_PACKET_SIZE];

    // Initialize position variable to keep track of the current position in the buffer.
    size_t current_position = 0;

    // Copy the message code attribute to the buffer at the current position.
    memcpy(upload_message_buffer, &m_message_code, sizeof(uint8_t));
    // Move the position to the next available space in the buffer.
    current_position += sizeof(uint8_t);

    // Copy the filename attribute to the buffer at the current position.
    memcpy(upload_message_buffer + current_position, m_filename, Config::FILE_NAME_LEN * sizeof(char));
    // Move the position to the next available space in the buffer.
    current_position += Config::FILE_NAME_LEN * sizeof(char);

    // Copy the file size attribute to the buffer at the current position.
    memcpy(upload_message_buffer + current_position, &m_file_size, sizeof(uint32_t));
    // Move the position to the next available space in the buffer.
    current_position += sizeof(uint32_t);

    // Add random bytes to the buffer to fill the remaining space.
    RAND_bytes(upload_message_buffer + current_position, Config::MAX_PACKET_SIZE - current_position);

    // Return the dynamically allocated buffer containing the serialized data.
    return upload_message_buffer;
}


/**
 * Function to deserialize data from the upload message buffer and construct a UploadM1 object
 * @param upload_message_buffer the serialized buffer with the message
 * @return Return the constructed UploadM1 object with deserialized data
 */
UploadM1 UploadM1::deserializeUploadM1(uint8_t *upload_message_buffer) {
    // Create an UploadM1 object.
    UploadM1 uploadM1;

    // Initialize position variable to keep track of the current position in the buffer.
    size_t current_position = 0;

    // Copy the value of the upload message code from the buffer to the uploadM1 object.
    memcpy(&uploadM1.m_message_code, upload_message_buffer, sizeof(uint8_t));
    // Move the position to the next available space in the buffer.
    current_position += sizeof(uint8_t);

    // Copy the value of filename from the buffer to the uploadM1 object.
    memcpy(uploadM1.m_filename, upload_message_buffer + current_position, Config::FILE_NAME_LEN * sizeof(char));
    // Move the position to the next available space in the buffer.
    current_position += Config::FILE_NAME_LEN * sizeof(char);

    // Copy the value of file size from the buffer to the uploadM1 object.
    memcpy(&uploadM1.m_file_size, upload_message_buffer + current_position, sizeof(uint32_t));

    // Return the uploadM1 object created.
    return uploadM1;
}


/**
 * Get the size of the UploadM1 message in bytes
 * @return Returns the total size of an UploadM1 message.
 */
size_t UploadM1::getSizeUploadM1() {
    size_t size = sizeof(m_message_code) + (Config::FILE_NAME_LEN * sizeof(char)) + sizeof(m_file_size);
    return size;
}

/**
 * Get the filename of the UploadM1 message
 * @return returns the filname of the UploadM1 message
 */
const char *UploadM1::getFilename() const {
    return m_filename;
}

/**
 * Get the file size of the UploadM1 message
 * @return returns the file size of the UploadM1 message
 */
uint32_t UploadM1::getFileSize() const {
    return m_file_size;
}



//-------------------------------------------UPLOAD MESSAGE 3+i-------------------------------------------//

/**
 * Default constructor of UploadMi class
 */
UploadMi::UploadMi() = default;


/**
 * Constructor of UploadMi class object. Used to create a i type of upload request message (UploadMi).
 * @param chunk is the the data chunk to be uploaded.
 * @param chunk_size is the size of the data chunk.
 */
UploadMi::UploadMi(uint8_t *chunk, int chunk_size) {
    // Set the message code attribute of the current object to UPLOAD_CHUNK.
    m_message_code = static_cast<uint8_t>(Message::UPLOAD_CHUNK);

    // Dynamically allocate memory for the m_chunk attribute to store the data chunk.
    m_chunk = new uint8_t[chunk_size];

    // Copy the content of the provided 'chunk' into the dynamically allocated 'm_chunk'.
    memcpy(m_chunk, chunk, chunk_size);

    // Set the m_chunk_size attribute to the provided 'chunk_size'.
    m_chunk_size = chunk_size;

}


/**
 * UploadMi object destructor. free the memory allocated for the chunk to prevent memory leaks
 */
UploadMi::~UploadMi() {
    // Release the dynamically allocated memory for m_chunk
    delete[] m_chunk;
}


/**
 * Function to serialize data for the type 3+i upload message into a byte buffer
 * @return Returns a dynamically allocated uint8_t array representing the serialized data.
 */
uint8_t *UploadMi::serializeUploadMi() {
    // Dynamically allocate memory (computed through the getSizeUploadMi function) for a buffer to hold the serialized data.
    uint8_t* upload_message_buffer = new uint8_t[UploadMi::getSizeUploadMi(m_chunk_size)];

    // Initialize position variable to keep track of the current position in the buffer.
    size_t current_position = 0;

    // Copy the value of m_message_code to the buffer at the current position.
    memcpy(upload_message_buffer, &m_message_code, sizeof(uint8_t));
    // Move the position to the next available space in the buffer.
    current_position += sizeof(uint8_t);

    // Copy the content of m_chunk to the buffer at the current position.
    memcpy(upload_message_buffer + current_position, m_chunk, m_chunk_size * sizeof(uint8_t));

    // Return the dynamically allocated buffer containing the serialized data.
    return upload_message_buffer;
}


/**
 * Function to deserialize data from the upload message buffer and construct a UploadMi object
 * @param upload_message_buffer is the serialized data to deserialize.
 * @param chunk_size is the size of the chunk data.
 * @return Return the constructed UploadMi object with deserialized data
 */
UploadMi UploadMi::deserializeUploadMi(uint8_t *upload_message_buffer, int chunk_size) {
    // Create an UploadMi object.
    UploadMi uploadMi;
    // Initialize position variable to keep track of the current position in the buffer.
    size_t current_position = 0;

    // Copy the value of the upload message code from the buffer to the uploadMi object.
    memcpy(&uploadMi.m_message_code, upload_message_buffer, sizeof(uint8_t));
    // Move the position to the next available space in the buffer.
    current_position += sizeof(uint8_t);

    // Dynamically allocate memory for the m_chunk attribute to store the deserialized data.
    uploadMi.m_chunk = new uint8_t[chunk_size];
    // Copy the chunk data from the buffer to the m_chunk attribute of the uploadMi object.
    memcpy(uploadMi.m_chunk, upload_message_buffer + current_position, chunk_size * sizeof(uint8_t));

    // Set the m_chunk_size attribute to the provided 'chunk_size'.
    uploadMi.m_chunk_size = chunk_size;

    // Return the populated uploadMi object.
    return uploadMi;
}


/**
 * Get the size of the UploadMi message in bytes
 * @param chunk_size is the size of the chunk data.
 * @return Returns the total size of an UploadMi message.
 */
size_t UploadMi::getSizeUploadMi(int chunk_size) {
    size_t size = sizeof(m_message_code) + (chunk_size * sizeof(uint8_t));
    return size;
}

/**
 * Get the chunk of the UploadMi message
 * @return returns the chunk of the UploadMi message
 */
uint8_t *UploadMi::getChunk() const {
    return m_chunk;
}
