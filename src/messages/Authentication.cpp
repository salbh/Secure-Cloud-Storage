#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include "Authentication.h"
#include "CodesManager.h"

using namespace std;

/**
 * @brief Default constructor for the AuthenticationM1 class.
 */
AuthenticationM1::AuthenticationM1() = default;

/**
 * @brief Parameterized constructor for the AuthenticationM1 class.
 * @param ephemeral_key The ephemeral key to be stored in the AuthenticationM1 object.
 * @param ephemeral_key_len The size of the ephemeral key.
 * @param username The username to be stored in the AuthenticationM1 object.
 */
AuthenticationM1::AuthenticationM1(uint8_t* ephemeral_key, int ephemeral_key_len, const string &username) {
    m_message_code = static_cast<uint8_t>(Message::AUTHENTICATION_REQUEST);
    // Initialize the ephemeral key with the provided data, and set the size
    memset(m_ephemeral_key, 0, sizeof(m_ephemeral_key));
    memcpy(m_ephemeral_key, ephemeral_key, ephemeral_key_len);
    m_ephemeral_key_len = static_cast<uint32_t>(ephemeral_key_len);

    // Initialize the username with the provided data
    memset(m_username, 0, sizeof(m_username));
    strncpy(m_username, username.c_str(), Config::USERNAME_LEN);
}

/**
 * @brief Get the total size of the AuthenticationM1 message.
 * @return The total size of the AuthenticationM1 message in bytes.
 */
size_t AuthenticationM1::getMessageSize() {
    size_t message_size = 0;

    // Calculate the total size by summing the sizes of individual components
    message_size += sizeof(uint8_t);
    message_size += EPHEMERAL_KEY_LEN * sizeof(uint8_t);
    message_size += sizeof(uint32_t);
    message_size += Config::USERNAME_LEN * sizeof(char);
    return message_size;
}

/**
 * @brief Serialize the AuthenticationM1 object into a byte buffer.
 * @return A dynamically allocated byte buffer containing the serialized data.
 */
uint8_t *AuthenticationM1::serialize() {
    // Allocate memory for the message buffer
    uint8_t* message_buffer = new (nothrow) uint8_t[AuthenticationM1::getMessageSize()];
    // Check if memory allocation was successful
    if (!message_buffer) {
        cerr << "AuthenticationM1 - Error during the serialization: Failed to allocate memory!" << endl;
        return nullptr;
    }

    size_t current_buffer_position = 0;
    // Copy the message code into the buffer
    memcpy(message_buffer, &m_message_code, sizeof(uint8_t));
    current_buffer_position += sizeof(uint8_t);
    // Copy the ephemeral key into the buffer
    memcpy(message_buffer + current_buffer_position, &m_ephemeral_key, EPHEMERAL_KEY_LEN * sizeof(uint8_t));
    current_buffer_position += EPHEMERAL_KEY_LEN * sizeof(uint8_t);

    // Convert the ephemeral key size to network byte order and copy to the buffer
    uint32_t ephemeral_key_len_big_end = htonl(m_ephemeral_key_len);
    memcpy(message_buffer + current_buffer_position, &ephemeral_key_len_big_end, sizeof(uint32_t));
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
AuthenticationM1 AuthenticationM1::deserialize(uint8_t *message_buffer) {
    AuthenticationM1 authenticationM1;

    size_t current_buffer_position = 0;

    // Copy the message code from the buffer
    memcpy(&authenticationM1.m_message_code, message_buffer, sizeof(uint8_t));
    current_buffer_position += sizeof(uint8_t);
    // Copy the ephemeral key from the buffer
    memcpy(&authenticationM1.m_ephemeral_key, message_buffer + current_buffer_position,
           EPHEMERAL_KEY_LEN * sizeof(uint8_t));
    current_buffer_position += EPHEMERAL_KEY_LEN * sizeof(uint8_t);

    // Convert the ephemeral key size from network byte order and copy to the object
    uint32_t ephemeral_key_len_big_end = 0;
    memcpy(&ephemeral_key_len_big_end, message_buffer + current_buffer_position, sizeof(uint32_t));
    authenticationM1.m_ephemeral_key_len = ntohl(ephemeral_key_len_big_end);
    current_buffer_position += sizeof(uint32_t);

    // Copy the username from the buffer
    memcpy(authenticationM1.m_username, message_buffer + current_buffer_position,
           Config::USERNAME_LEN * sizeof(char));
    // Return the deserialized AuthenticationM1 message
    return authenticationM1;
}

const char *AuthenticationM1::getMUsername() const {
    return m_username;
}

/**
 * @brief Default constructor for the AuthenticationM3 class.
 */
AuthenticationM3::AuthenticationM3() = default;

/**
 * @brief Parameterized constructor for the AuthenticationM3 class.
 * @param ephemeral_key The ephemeral key to be stored in the AuthenticationM3 object.
 * @param ephemeral_key_len The size of the ephemeral key.
 * @param iv The initialization vector used in the encryption process.
 * @param aad The additional authenticated data.
 * @param tag The authenticationRequest tag generated during encryption.
 * @param encrypted_digital_signature The encrypted digital signature.
 * @param serialized_certificate The serialized certificate.
 * @param serialized_certificate_len The size of the serialized certificate.
 */
AuthenticationM3::AuthenticationM3(uint8_t *ephemeral_key, uint32_t ephemeral_key_len, unsigned char *iv,
                                   unsigned char *aad, unsigned char *tag, uint8_t *encrypted_digital_signature,
                                   uint8_t *serialized_certificate, uint32_t serialized_certificate_len) {
    // Initialize ephemeral key with provided data and set its size
    memset(m_ephemeral_key, 0, sizeof(m_ephemeral_key));
    memcpy(m_ephemeral_key, ephemeral_key, ephemeral_key_len);
    m_ephemeral_key_len = static_cast<uint32_t>(ephemeral_key_len);

    // Copy IV, AAD, Tag, and encrypted digital signature
    memcpy(m_iv, iv, Config::IV_LEN * sizeof(uint8_t));
    memcpy(m_aad, aad, Config::AAD_LEN * sizeof(char));
    memcpy(m_tag, tag, Config::AES_TAG_LEN * sizeof(char));
    memcpy(m_encrypted_digital_signature, encrypted_digital_signature,
           ENCRYPTED_SIGNATURE_LEN * sizeof(uint8_t));

    // Copy serialized certificate and zero-pad the remaining space
    memcpy(m_serialized_certificate, serialized_certificate, serialized_certificate_len);
    memset(m_serialized_certificate + serialized_certificate_len, 0,
           MAX_SERIALIZED_CERTIFICATE_LEN - serialized_certificate_len);
    m_serialized_certificate_len = static_cast<uint32_t>(serialized_certificate_len);
}

/**
 * @brief Get the total size of the AuthenticationM3 message.
 * @return The total size of the AuthenticationM3 message in bytes.
 */
int AuthenticationM3::getMessageSize() {
    int message_size = 0;

    // Calculate the total size by summing the sizes of individual components
    message_size += EPHEMERAL_KEY_LEN * sizeof(uint8_t);
    message_size += sizeof(uint32_t);
    message_size += Config::IV_LEN * sizeof(uint8_t);
    message_size += Config::AAD_LEN * sizeof(char);
    message_size += Config::AES_TAG_LEN * sizeof(char);
    message_size += ENCRYPTED_SIGNATURE_LEN * sizeof(uint8_t);
    message_size += MAX_SERIALIZED_CERTIFICATE_LEN * sizeof(uint8_t);
    message_size += sizeof(uint32_t);

    return message_size;
}

/**
 * @brief Serialize the AuthenticationM3 object into a byte buffer.
 * @return A dynamically allocated byte buffer containing the serialized data.
 */
uint8_t *AuthenticationM3::serialize() {
    // Allocate memory for the message buffer
    uint8_t* message_buffer = new (nothrow) uint8_t[AuthenticationM3::getMessageSize()];
    // Check if memory allocation was successful
    if (!message_buffer) {
        cerr << "AuthenticationM3 - Error during the serialization: Failed to allocate memory!" << endl;
        return nullptr;
    }

    size_t current_buffer_position = 0;

    // Copy ephemeral key and its size to the buffer
    memcpy(message_buffer + current_buffer_position, &m_ephemeral_key, EPHEMERAL_KEY_LEN * sizeof(uint8_t));
    current_buffer_position += EPHEMERAL_KEY_LEN * sizeof(uint8_t);
    uint32_t ephemeral_key_len_big_end = htonl(m_ephemeral_key_len);
    memcpy(message_buffer + current_buffer_position, &ephemeral_key_len_big_end, sizeof(uint32_t));
    current_buffer_position += sizeof(uint32_t);

    // Copy IV, AAD, Tag, encrypted digital signature, serialized certificate, and its size
    memcpy(message_buffer + current_buffer_position, &m_iv,
           Config::IV_LEN * sizeof(uint8_t));
    current_buffer_position += Config::IV_LEN * sizeof(uint8_t);
    memcpy(message_buffer + current_buffer_position, &m_aad, Config::AAD_LEN * sizeof(char));
    current_buffer_position += Config::AAD_LEN * sizeof(char);
    memcpy(message_buffer + current_buffer_position, &m_tag, Config::AES_TAG_LEN * sizeof(char));
    current_buffer_position += Config::AES_TAG_LEN * sizeof(char);
    memcpy(message_buffer + current_buffer_position, &m_encrypted_digital_signature,
           ENCRYPTED_SIGNATURE_LEN * sizeof(uint8_t));
    current_buffer_position += ENCRYPTED_SIGNATURE_LEN * sizeof(uint8_t);
    memcpy(message_buffer + current_buffer_position, &m_serialized_certificate,
           MAX_SERIALIZED_CERTIFICATE_LEN * sizeof(uint8_t));
    current_buffer_position += MAX_SERIALIZED_CERTIFICATE_LEN * sizeof(uint8_t);
    uint32_t serialized_certificate_len_big_end = htonl(m_serialized_certificate_len);
    memcpy(message_buffer + current_buffer_position, &serialized_certificate_len_big_end, sizeof(uint32_t));

    return message_buffer;
}

/**
 * @brief Deserialize a byte buffer into an AuthenticationM3 object.
 * @param message_buffer The byte buffer containing the serialized data.
 * @return An AuthenticationM3 object with deserialized data.
 */
AuthenticationM3 AuthenticationM3::deserialize(uint8_t *message_buffer) {
    AuthenticationM3 authenticationM3;

    size_t current_buffer_position = 0;

    // Copy ephemeral key from the buffer
    memcpy(&authenticationM3.m_ephemeral_key, message_buffer + current_buffer_position,
           EPHEMERAL_KEY_LEN * sizeof(uint8_t));
    current_buffer_position += EPHEMERAL_KEY_LEN * sizeof(uint8_t);

    // Convert ephemeral key size from network byte order and copy to the object
    uint32_t ephemeral_key_len_big_end = 0;
    memcpy(&ephemeral_key_len_big_end, message_buffer + current_buffer_position, sizeof(uint32_t));
    authenticationM3.m_ephemeral_key_len = ntohl(ephemeral_key_len_big_end);
    current_buffer_position += sizeof(uint32_t);

    // Copy IV, AAD, Tag, encrypted digital signature, serialized certificate, and its size
    memcpy(&authenticationM3.m_iv, message_buffer + current_buffer_position,
           Config::IV_LEN* sizeof(uint8_t));
    current_buffer_position += Config::IV_LEN * sizeof(uint8_t);
    memcpy(&authenticationM3.m_aad, message_buffer + current_buffer_position,
           Config::AAD_LEN * sizeof(char));
    current_buffer_position += Config::AAD_LEN * sizeof(char);
    memcpy(&authenticationM3.m_tag, message_buffer + current_buffer_position,
           Config::AES_TAG_LEN * sizeof(char));
    current_buffer_position += Config::AES_TAG_LEN * sizeof(char);
    memcpy(&authenticationM3.m_encrypted_digital_signature, message_buffer + current_buffer_position,
           ENCRYPTED_SIGNATURE_LEN * sizeof(uint8_t));
    current_buffer_position += ENCRYPTED_SIGNATURE_LEN * sizeof(uint8_t);
    memcpy(&authenticationM3.m_serialized_certificate, message_buffer + current_buffer_position,
           MAX_SERIALIZED_CERTIFICATE_LEN * sizeof(uint8_t));
    current_buffer_position += MAX_SERIALIZED_CERTIFICATE_LEN * sizeof(uint8_t);

    uint32_t serialized_certificate_len_big_end = 0;
    memcpy(&serialized_certificate_len_big_end, message_buffer + current_buffer_position, sizeof(uint32_t));
    authenticationM3.m_serialized_certificate_len = htonl(serialized_certificate_len_big_end);

    return authenticationM3;
}

/**
 * @brief Default constructor for the AuthenticationM4 class.
 */
AuthenticationM4::AuthenticationM4() = default;

/**
 * @brief Parameterized constructor for the AuthenticationM4 class.
 * @param iv The initialization vector used in the encryption process.
 * @param aad The additional authenticated data.
 * @param tag The authenticationRequest tag generated during encryption.
 * @param encrypted_digital_signature The encrypted digital signature.
 */
AuthenticationM4::AuthenticationM4(unsigned char *iv, unsigned char *aad, unsigned char *tag,
                                   uint8_t *encrypted_digital_signature) {
    // Copy IV, AAD, Tag, and encrypted digital signature
    memcpy(m_iv, iv, Config::IV_LEN * sizeof(uint8_t));
    memcpy(m_aad, aad, Config::AAD_LEN * sizeof(char));
    memcpy(m_tag, tag, Config::AES_TAG_LEN * sizeof(char));
    memcpy(m_encrypted_digital_signature, encrypted_digital_signature,
           ENCRYPTED_SIGNATURE_LEN * sizeof(uint8_t));
}

/**
 * @brief Get the total size of the AuthenticationM4 message.
 * @return The total size of the AuthenticationM4 message in bytes.
 */
int AuthenticationM4::getMessageSize() {
    int message_size = 0;

    // Calculate the total size by summing the sizes of individual components
    message_size += Config::IV_LEN * sizeof(uint8_t);
    message_size += Config::AAD_LEN * sizeof(char);
    message_size += Config::AES_TAG_LEN * sizeof(char);
    message_size += ENCRYPTED_SIGNATURE_LEN * sizeof(uint8_t);

    return message_size;
}

/**
 * @brief Serialize the AuthenticationM4 object into a byte buffer.
 * @return A dynamically allocated byte buffer containing the serialized data.
 */
uint8_t *AuthenticationM4::serialize() {
    // Allocate memory for the message buffer
    uint8_t* message_buffer = new (nothrow) uint8_t[AuthenticationM4::getMessageSize()];
    // Check if memory allocation was successful
    if (!message_buffer) {
        cerr << "AuthenticationM4 - Error during the serialization: Failed to allocate memory!" << endl;
        return nullptr;
    }

    size_t current_buffer_position = 0;

    // Copy IV, AAD, Tag, and encrypted digital signature
    memcpy(message_buffer + current_buffer_position, &m_iv,
           Config::IV_LEN * sizeof(uint8_t));
    current_buffer_position += Config::IV_LEN * sizeof(uint8_t);
    memcpy(message_buffer + current_buffer_position, &m_aad, Config::AAD_LEN * sizeof(char));
    current_buffer_position += Config::AAD_LEN * sizeof(char);
    memcpy(message_buffer + current_buffer_position, &m_tag, Config::AES_TAG_LEN * sizeof(char));
    current_buffer_position += Config::AES_TAG_LEN * sizeof(char);
    memcpy(message_buffer + current_buffer_position, &m_encrypted_digital_signature,
           ENCRYPTED_SIGNATURE_LEN * sizeof(uint8_t));
    current_buffer_position += ENCRYPTED_SIGNATURE_LEN * sizeof(uint8_t);

    return message_buffer;
}

/**
 * @brief Deserialize a byte buffer into an AuthenticationM4 object.
 * @param message_buffer The byte buffer containing the serialized data.
 * @return An AuthenticationM4 object with deserialized data.
 */
AuthenticationM4 AuthenticationM4::deserialize(uint8_t *message_buffer) {
    AuthenticationM4 authenticationM4;

    size_t current_buffer_position = 0;

    // Copy IV, AAD, Tag, and encrypted digital signature
    memcpy(&authenticationM4.m_iv, message_buffer + current_buffer_position,
           Config::IV_LEN * sizeof(uint8_t));
    current_buffer_position += Config::IV_LEN * sizeof(uint8_t);
    memcpy(&authenticationM4.m_aad, message_buffer + current_buffer_position,
           Config::AAD_LEN * sizeof(char));
    current_buffer_position += Config::AAD_LEN * sizeof(char);
    memcpy(&authenticationM4.m_tag, message_buffer + current_buffer_position,
           Config::AES_TAG_LEN * sizeof(char));
    current_buffer_position += Config::AES_TAG_LEN * sizeof(char);
    memcpy(&authenticationM4.m_encrypted_digital_signature, message_buffer + current_buffer_position,
           ENCRYPTED_SIGNATURE_LEN * sizeof(uint8_t));

    return authenticationM4;
}
