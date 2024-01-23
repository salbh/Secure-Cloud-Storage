#ifndef SECURE_CLOUD_STORAGE_AUTHENTICATION_H
#define SECURE_CLOUD_STORAGE_AUTHENTICATION_H

#include <cstdint>
#include <string>
#include <openssl/evp.h>
#include "Config.h"

using namespace std;

namespace {
    const uint16_t EPHEMERAL_KEY_LEN = 1024;
    const uint16_t ENCRYPTED_SIGNATURE_LEN = 128;
    const uint16_t MAX_SERIALIZED_CERTIFICATE_LEN = 1500;
}

class AuthenticationM1 {
private:
    uint8_t m_message_code;
    uint8_t m_ephemeral_key[EPHEMERAL_KEY_LEN];
    uint32_t m_ephemeral_key_len;
    char m_username[Config::USERNAME_LEN];

public:
    AuthenticationM1();
    AuthenticationM1(uint8_t* ephemeral_key, int ephemeral_key_len, const string& username);

    static size_t getMessageSize();

    uint8_t* serialize();
    static AuthenticationM1 deserialize(uint8_t* message_buffer);

    const char *getMUsername() const;

    const uint8_t *getMEphemeralKey() const;

    uint32_t getMEphemeralKeyLen() const;
};

class AuthenticationM3 {
private:
    uint8_t m_ephemeral_key[EPHEMERAL_KEY_LEN];
    uint32_t m_ephemeral_key_len;
    unsigned char m_iv[Config::IV_LEN];
    unsigned char m_aad[Config::AAD_LEN];
    unsigned char m_tag[Config::AES_TAG_LEN];
    uint8_t m_encrypted_digital_signature[ENCRYPTED_SIGNATURE_LEN];
    uint8_t m_serialized_certificate[MAX_SERIALIZED_CERTIFICATE_LEN];
    uint32_t m_serialized_certificate_len;

public:
    AuthenticationM3();
    AuthenticationM3(uint8_t *ephemeral_key, uint32_t ephemeral_key_len, unsigned char *iv, unsigned char *aad,
                     unsigned char *tag, unsigned char *encrypted_digital_signature, uint8_t *serialized_certificate,
                     uint32_t serialized_certificate_len);

    static int getMessageSize();
    const unsigned char *getMEphemeralKey() const;
    uint32_t getMEphemeralKeyLen() const;
    const uint8_t *getMSerializedCertificate() const;
    uint32_t getMSerializedCertificateLen() const;

    const uint8_t *getMEncryptedDigitalSignature() const;

    const unsigned char *getMIv() const;
    const unsigned char *getMAad() const;
    const unsigned char *getMTag() const;

    uint8_t* serialize();
    static AuthenticationM3 deserialize(uint8_t* message_buffer);
};

class AuthenticationM4 {
private:
    unsigned char* m_iv;
    unsigned char* m_aad[Config::AAD_LEN];
    unsigned char* m_tag[Config::AES_TAG_LEN];
    uint8_t m_encrypted_digital_signature[ENCRYPTED_SIGNATURE_LEN];

public:
    AuthenticationM4();
    AuthenticationM4(unsigned char *iv, unsigned char *aad, unsigned char *tag, uint8_t *encrypted_digital_signature);

    int getMessageSize();

    uint8_t* serialize();
    AuthenticationM4 deserialize(uint8_t* message_buffer);



};

#endif //SECURE_CLOUD_STORAGE_AUTHENTICATION_H