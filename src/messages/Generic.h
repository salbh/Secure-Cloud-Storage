#ifndef SECURE_CLOUD_STORAGE_GENERIC_H
#define SECURE_CLOUD_STORAGE_GENERIC_H

#include <iostream>

class Generic {

private:
    unsigned char *m_iv;
    unsigned char *m_aad;
    unsigned char *m_tag;
    uint8_t *m_ciphertext;
    size_t m_ciphertext_len;




public:
    Generic(const unsigned char *session_key, uint32_t counter, uint8_t* plaintext, size_t plaintext_size);
    int decrypt(const unsigned char *session_key, unsigned char *plaintext, int plaintext_len);
    uint8_t *serialize();
    Generic deserialize(uint8_t *message_buffer);
    size_t getSize();




};


#endif //SECURE_CLOUD_STORAGE_GENERIC_H
