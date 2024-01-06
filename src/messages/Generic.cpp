#include "Generic.h"


Generic::Generic(const unsigned char *session_key, uint32_t counter, uint8_t *plaintext, size_t plaintext_size) {
    /*
     * Set AAD (cast of the counter for the AAD format: uint32_t to unsigned char*)
     * Set TAG (initialization to nullptr)
     * Plaintext Encryption (generate ciphertext and tag)
     * Get IV and Set (function of AesGcm)
     */

}

int Generic::decrypt(const unsigned char *session_key, unsigned char *plaintext, int plaintext_len) {
    return 0;
}

uint8_t *Generic::serialize() {
    return nullptr;
}

Generic Generic::deserialize(uint8_t *message_buffer) {
    return Generic(nullptr, 0, nullptr, 0);
}

size_t Generic::getSize() {
    return 0;
}
