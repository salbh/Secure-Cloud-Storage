#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "./CodesManager.h"
#include "Logout.h"



Logout::Logout() {}

/**
 * Logout Message object constructor
 * @param counter
 */
Logout::Logout(uint32_t counter) {
    m_message_code = static_cast<uint8_t>(Message::LOGOUT_REQUEST);
    m_counter = counter;
}

//
/**
 * Function to serialize data into a byte buffer
 * @return the serialized buffer with the logout message
 */
uint8_t* Logout::serializeLogoutMessage() {

    // Allocate memory for the logout message buffer using the size defined by MESSAGE_CODE_PACKET_SIZE
    uint8_t* logout_message_buffer = new uint8_t[MESSAGE_CODE_PACKET_SIZE];

    // Initialize position variable to keep track of the current position in the buffer
    size_t current_buffer_position = 0;

    // Copy the message code to the buffer and update the position
    memcpy(logout_message_buffer, &m_message_code, sizeof(uint8_t));
    current_buffer_position += sizeof(uint8_t);

    // Copy the counter value to the buffer and update the position
    memcpy(logout_message_buffer + current_buffer_position, &m_message_code, sizeof(uint32_t));
    current_buffer_position += sizeof(uint32_t);

    /* Generate random bytes and add them to the buffer to fill the remaining space.
     * to ensure that the entire buffer is populated with data, making it more difficult for an attacker
     * to infer information about the content of the message.
     * The number of random bytes added is calculated as MESSAGE_CODE_PACKET_SIZE - position.
     */
    RAND_bytes(logout_message_buffer + current_buffer_position, MESSAGE_CODE_PACKET_SIZE - current_buffer_position);

    // Return the serialized buffer
    return logout_message_buffer;
}


//
/**
 * Static function to deserialize data from a logout message buffer and construct a Logout object
 * @param logout_message_buffer the serialized buffer with the logout message
 * @return Return the constructed Logout object with deserialized data
 */
Logout Logout::deserializeLogoutMessage(uint8_t* logout_message_buffer) {

    // Create a Logout object to store the deserialized data
    Logout logout_message;

    // Initialize position variable to keep track of the current position in the buffer
    size_t logout_message_position = 0;

    // Copy the message code from the buffer to logout_message.m_message_code and update the position
    memcpy(&logout_message.m_message_code, logout_message_buffer, sizeof(uint8_t));
    logout_message_position += sizeof(uint8_t);

    // Copy the counter value from the buffer to logout_message.m_counter
    memcpy(&logout_message.m_counter, logout_message_buffer + logout_message_position, sizeof(uint32_t));

    // Return the constructed Logout object with deserialized data
    return logout_message;
}

