#include "AesGcm.h"
#include <iostream>
#include <cstring>

using namespace std;

AesGcm::AesGcm(const unsigned char* key) {
    m_cipher = EVP_aes_128_gcm();
    m_block_size = EVP_CIPHER_block_size(m_cipher);
    m_iv_len = EVP_CIPHER_iv_length(m_cipher);

    m_key_len = EVP_CIPHER_key_length(m_cipher);
    m_key = new unsigned char[m_key_len];
    memcpy(m_key, key, m_key_len);
}

AesGcm::~AesGcm() {
    OPENSSL_cleanse(m_key, m_key_len);
    delete[] m_key;
}

int AesGcm::encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* aad, int aad_len,
                    unsigned char*& ciphertext, unsigned char* tag) {
    int len;
    int ciphertext_len;
    // Check for integer overflow
    if (plaintext_len + m_block_size > INT_MAX) {
        cerr << "AesGCM - Error during encryption: Integer overflow (file too large)" << endl;
        return -1;
    }
    // Allocate memory for m_ciphertext buffer
    m_ciphertext = new (nothrow) unsigned char[plaintext_len + m_block_size];
    if (!m_ciphertext) {
        cerr << "AesGCM - Error during encryption: Failed to allocate memory for m_ciphertext" << endl;
        return -1;
    }
    // Generate IV
    m_iv = new unsigned char[m_iv_len];
    RAND_poll();
    if (RAND_bytes(m_iv, m_iv_len) != 1) {
        return handleErrorEncrypt("RAND_bytes for IV generation failed");
    }
    // Initialize the encryption operation.
    m_ctx = EVP_CIPHER_CTX_new();
    if (!m_ctx) {
        return handleErrorEncrypt("EVP_CIPHER_CTX_new() failed");
    }
    // Initialize key and IV
    if (!EVP_EncryptInit_ex(m_ctx, m_cipher, nullptr, m_key, m_iv)) {
        return handleErrorEncrypt("EVP_EncryptInit_ex failed");
    }
    // Provide any AAD data.
    if (!EVP_EncryptUpdate(m_ctx, nullptr, &len, aad, aad_len)) {
        return handleErrorEncrypt("EVP_EncryptUpdate for AAD failed");
    }
    // Provide the message to be encrypted, and obtain the encrypted output.
    if (!EVP_EncryptUpdate(m_ctx, m_ciphertext, &len, plaintext, plaintext_len)) {
        return handleErrorEncrypt("EVP_EncryptUpdate for encryption failed");
    }
    ciphertext_len = len;
    // Finalize the encryption.
    if (!EVP_EncryptFinal_ex(m_ctx, m_ciphertext + len, &len)) {
        return handleErrorEncrypt("EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;
    // Get the tag
    if (!EVP_CIPHER_CTX_ctrl(m_ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag)) {
        return handleErrorEncrypt("EVP_CIPHER_CTX_ctrl for tag failed");
    }
    ciphertext = m_ciphertext;

    EVP_CIPHER_CTX_free(m_ctx);
    delete[] m_iv;
    delete[] m_ciphertext;

    return ciphertext_len;
}

int AesGcm::decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* aad, int aad_len,
                    unsigned char* iv, unsigned char* tag, unsigned char*& plaintext) {
    int len;
    int plaintext_len;
    int ret;

    // Allocate memory for m_plaintext buffer
    m_plaintext = new (nothrow) unsigned char[ciphertext_len];
    if (!m_plaintext) {
        cerr << "AesGCM - Error during decryption: Failed to allocate memory for plaintext" << endl;
        return -1;
    }
    // Initialize the decryption operation.
    m_ctx = EVP_CIPHER_CTX_new();
    if (!m_ctx) {
        return handleErrorDecrypt("EVP_CIPHER_CTX_new() for decryption failed");
    }
    // Initialize key and IV
    if (!EVP_DecryptInit_ex(m_ctx, m_cipher, nullptr, m_key, iv)) {
        return handleErrorDecrypt("EVP_DecryptInit_ex failed");
    }
    // Provide any AAD data.
    if (!EVP_DecryptUpdate(m_ctx, nullptr, &len, aad, aad_len)) {
        return handleErrorDecrypt("EVP_DecryptUpdate for AAD failed");
    }
    // Provide the message to be decrypted, and obtain the plaintext output.
    if (!EVP_DecryptUpdate(m_ctx, m_plaintext, &len, ciphertext, ciphertext_len)) {
        return handleErrorDecrypt("EVP_DecryptUpdate for decryption failed");
    }
    plaintext_len = len;

    // Set expected tag value.
    if (!EVP_CIPHER_CTX_ctrl(m_ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN, tag)) {
        return handleErrorDecrypt("EVP_CIPHER_CTX_ctrl for tag failed");
    }
    // Finalize the decryption.
    ret = EVP_DecryptFinal_ex(m_ctx, m_plaintext + len, &len);

    plaintext = m_plaintext;
    EVP_CIPHER_CTX_free(m_ctx);
    delete[] m_plaintext;

    if (ret > 0) {
        // Success
        plaintext_len += len;
        return plaintext_len;
    } else {
        // Verify failed
        return -1;
    }
}

int AesGcm::handleErrorEncrypt(const char* msg) {
    cerr << "AesGCM - Error during encryption: " << msg << endl;
    delete[] m_iv;
    delete[] m_ciphertext;
    return -1;
}

int AesGcm::handleErrorDecrypt(const char* msg) {
    cerr << "AesGCM - Error during decryption: " << msg << endl;
    delete m_plaintext;
    return -1;
}
