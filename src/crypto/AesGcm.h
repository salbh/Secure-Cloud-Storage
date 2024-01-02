#ifndef SECURE_CLOUD_STORAGE_AESGCM_H
#define SECURE_CLOUD_STORAGE_AESGCM_H

#include <cstdint>
#include <openssl/evp.h>
#include <openssl/rand.h>

class AesGcm {

private:
    const EVP_CIPHER *m_cipher;
    EVP_CIPHER_CTX *m_ctx;
    unsigned char *m_key;
    int m_key_len;
    int m_iv_len;
    int m_block_size;
    unsigned char *m_ciphertext;
    unsigned char *m_plaintext;
    unsigned char *m_iv;

public:
    AesGcm(const unsigned char *key);

    ~AesGcm();

    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
                int aad_len, unsigned char *&ciphertext, unsigned char *tag);

    int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
                int aad_len, unsigned char *iv, unsigned char *tag, unsigned char *&plaintext);

    int handleErrorEncrypt(const char *msg);

    int handleErrorDecrypt(const char *msg);

    static constexpr unsigned int AES_TAG_LEN = 16;

    unsigned char *getIV();

    int getIVLen() const;
};

#endif //SECURE_CLOUD_STORAGE_AESGCM_H