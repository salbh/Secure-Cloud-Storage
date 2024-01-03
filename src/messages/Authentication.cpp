#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include "Authentication.h"

using namespace std;

/**
 * @brief Default constructor for the AuthenticationM1 class.
 */
AuthenticationM1::AuthenticationM1() = default;

/**
 * @brief Parameterized constructor for the AuthenticationM1 class.
 * @param ephemeral_key The ephemeral key to be stored in the AuthenticationM1 object.
 * @param ephemeral_key_size The size of the ephemeral key.
 * @param username The username to be stored in the AuthenticationM1 object.
 */
AuthenticationM1::AuthenticationM1(uint8_t* ephemeral_key, int ephemeral_key_size, const string &username) {
    // Initialize the ephemeral key with the provided data, and set the size
    memset(m_ephemeral_key, 0, sizeof(m_ephemeral_key));
    memcpy(m_ephemeral_key, ephemeral_key, ephemeral_key_size);
    m_ephemeral_key_size = static_cast<uint32_t>(ephemeral_key_size);

    // Initialize the username with the provided data
    memset(m_username, 0, sizeof(m_username));
    strncpy(m_username, username.c_str(), Config::USERNAME_LEN);
}

/**
 * @brief Get the total size of the AuthenticationM1 message.
 * @return The total size of the AuthenticationM1 message in bytes.
 */
int AuthenticationM1::getMessageSize() {
    int message_size = 0;

    // Calculate the total size by summing the sizes of individual components
    message_size += EPHEMERAL_KEY_LEN * sizeof(uint8_t);
    message_size += sizeof(uint32_t);
    message_size += Config::USERNAME_LEN * sizeof(char);
    return message_size;
}

/**
 * @brief Serialize the AuthenticationM1 object into a byte buffer.
 * @return A dynamically allocated byte buffer containing the serialized data.
 */
uint8_t *AuthenticationM1::serializeAuthenticationM1() {
    // Allocate memory for the message buffer
    uint8_t* message_buffer = new (nothrow) uint8_t[AuthenticationM1::getMessageSize()];
    // Check if memory allocation was successful
    if (!message_buffer) {
        cerr << "AuthenticationM1 - Error during the serialization: Failed to allocate memory!" << endl;
        return nullptr;
    }

    size_t current_buffer_position = 0;
    // Copy the ephemeral key into the buffer
    memcpy(message_buffer, &m_ephemeral_key, EPHEMERAL_KEY_LEN * sizeof(uint8_t));
    current_buffer_position += EPHEMERAL_KEY_LEN * sizeof(uint8_t);

    // Convert the ephemeral key size to network byte order and copy to the buffer
    uint32_t ephemeral_key_size_big_end = htonl(m_ephemeral_key_size);
    memcpy(message_buffer + current_buffer_position, &ephemeral_key_size_big_end, sizeof(uint32_t));
    current_buffer_position += sizeof(uint32_t);

    // Copy the username into the buffer
    memcpy(message_buffer + current_buffer_position, m_username, Config::USERNAME_LEN * sizeof(char));

    // Return the serialized AuthenticationM1 message
    return message_buffer;
}

/**
 * @brief Deserialize a byte buffer into an AuthenticationM1 object.
 * @param message_buffer The byte buffer containing the serialized data.
 * @return An AuthenticationM1 object with deserialized data.
 */
AuthenticationM1 AuthenticationM1::deserializeAuthenticationM1(uint8_t *message_buffer) {
    AuthenticationM1 authenticationM1;

    size_t current_buffer_position = 0;

    // Copy the ephemeral key from the buffer
    memcpy(&authenticationM1.m_ephemeral_key, message_buffer, EPHEMERAL_KEY_LEN * sizeof(uint8_t));
    current_buffer_position += EPHEMERAL_KEY_LEN * sizeof(uint8_t);

    // Convert the ephemeral key size from network byte order and copy to the object
    uint32_t ephemeral_key_size_big_end = 0;
    memcpy(&ephemeral_key_size_big_end, message_buffer + current_buffer_position, sizeof(uint32_t));
    authenticationM1.m_ephemeral_key_size = ntohl(ephemeral_key_size_big_end);
    current_buffer_position += sizeof(uint32_t);

    // Copy the username from the buffer
    memcpy(authenticationM1.m_username, message_buffer + current_buffer_position,
           Config::USERNAME_LEN * sizeof(char));
    // Return the deserialized AuthenticationM1 message
    return authenticationM1;
}
