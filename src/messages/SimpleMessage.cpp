#include <string>
#include <cstring>
#include <openssl/rand.h>

#include "SimpleMessage.h"
#include "Config.h"


/**
 * Default constructor of SimpleMessage class
 */
SimpleMessage::SimpleMessage() = default;


/**
 * Simple Message object constructor
 * @param message_code code of the message request
 */
SimpleMessage::SimpleMessage(uint8_t message_code) {
    m_message_code = message_code;
}


/**
 * Function to serialize data into a byte buffer
 * @return the serialized buffer with the message
 */
uint8_t* SimpleMessage::serialize() {

    // Allocate memory for the message buffer using the size defined by MAX_PACKET_SIZE
    uint8_t* message_buffer = new uint8_t[Config::MAX_PACKET_SIZE];

    // Initialize position variable to keep track of the current position in the buffer
    size_t current_buffer_position = 0;

    // Copy the message code to the buffer and update the position
    memcpy(message_buffer, &m_message_code, sizeof(uint8_t));
    current_buffer_position += sizeof(uint8_t);

    /* Generate random bytes and add them to the buffer to fill the remaining space.
     * to ensure that the entire buffer is populated with data, making it more difficult for an attacker
     * to infer information about the content of the message.
     * The number of random bytes added is calculated as MAX_PACKET_SIZE - position.
     */
    RAND_bytes(message_buffer + current_buffer_position, Config::MAX_PACKET_SIZE - current_buffer_position);

    // Return the serialized buffer
    return message_buffer;
}

uint8_t SimpleMessage::getMessageCode() const {
    return m_message_code;
}

/**
 * Function to deserialize data from a message buffer and construct a Simple Message object
 * @param message_buffer the serialized buffer with the message
 * @return Return the constructed Simple Message object with deserialized data
 */
SimpleMessage SimpleMessage::deserialize(uint8_t* message_buffer) {

    // Create a Simple Message object to store the deserialized data
    SimpleMessage message;

    // Copy the message code from the buffer to message.m_message_code and update the position
    memcpy(&message.m_message_code, message_buffer, sizeof(uint8_t));

    // Return the constructed Simple Message object with deserialized data
    return message;
}

size_t SimpleMessage::getSize() {
    return Config::MAX_PACKET_SIZE;
}
