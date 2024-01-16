#include "AesGcm.h"
#include <iostream>
#include <cstring>
#include "Config.h"

using namespace std;

/**
 * Constructor for AesGcm class
 * @param key The encryption key
 */
AesGcm::AesGcm(unsigned char *key) {
    // Set the cipher to AES-128 GCM
    m_cipher = EVP_aes_128_gcm();
    // Get IV length for the cipher
    m_iv_len = EVP_CIPHER_iv_length(m_cipher);
    // Get key length and allocate memory for the key
    m_key_len = EVP_CIPHER_key_length(m_cipher);
    m_key = new unsigned char[m_key_len];
    memcpy(m_key, key, m_key_len);
}

/**
 * Destructor for AesGcm class
 * Cleans up resources and securely clears sensitive data
 */
AesGcm::~AesGcm() {
    // Cleanse and delete the key
    OPENSSL_cleanse(m_key, m_key_len);
    delete[] m_key;
}

/**
 * Encryption function
 * @param plaintext The input plaintext
 * @param plaintext_len Length of the plaintext
 * @param aad Additional authenticated data
 * @param aad_len Length of the additional authenticated data
 * @param ciphertext The output ciphertext
 * @param tag The authentication tag
 * @return Length of the ciphertext on success, -1 on failure
 */
int AesGcm::encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len,
                    unsigned char *&ciphertext, unsigned char *tag) {
    int len;
    int ciphertext_len;
    // Allocate memory for m_ciphertext buffer
    m_ciphertext = new(nothrow) unsigned char[plaintext_len];
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
    if (!EVP_CIPHER_CTX_ctrl(m_ctx, EVP_CTRL_GCM_GET_TAG, Config::AES_TAG_LEN, tag)) {
        return handleErrorEncrypt("EVP_CIPHER_CTX_ctrl for tag failed");
    }
    ciphertext = m_ciphertext;
    EVP_CIPHER_CTX_free(m_ctx);

    return ciphertext_len;
}

/**
 * Decryption function
 * @param ciphertext The input ciphertext
 * @param ciphertext_len Length of the ciphertext
 * @param aad Additional authenticated data
 * @param aad_len Length of the additional authenticated data
 * @param iv The initialization vector
 * @param tag The authentication tag
 * @param plaintext The output plaintext
 * @return Length of the plaintext on success, -1 on failure
 */
int AesGcm::decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len,
                    unsigned char *iv, unsigned char *tag, unsigned char *&plaintext) {
    int len;
    int plaintext_len;
    int ret;

    // Allocate memory for m_plaintext buffer
    m_plaintext = new(nothrow) unsigned char[ciphertext_len];
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
    if (!EVP_CIPHER_CTX_ctrl(m_ctx, EVP_CTRL_GCM_SET_TAG, Config::AES_TAG_LEN, tag)) {
        return handleErrorDecrypt("EVP_CIPHER_CTX_ctrl for tag failed");
    }
    // Finalize the decryption.
    ret = EVP_DecryptFinal_ex(m_ctx, m_plaintext + len, &len);

    plaintext = m_plaintext;
    EVP_CIPHER_CTX_free(m_ctx);

    if (ret > 0) {
        // Success
        plaintext_len += len;
        return plaintext_len;
    } else {
        // Verify failed
        delete[] m_plaintext;
        cerr << "AesGCM - Error during decryption: EVP_DecryptFinal_ex failed" << endl;
        return -1;
    }
}

/**
 * Error handling function for encryption
 * @param msg Error message
 * @return -1 to indicate an error
 */
int AesGcm::handleErrorEncrypt(const char *msg) {
    cerr << "AesGCM - Error during encryption: " << msg << endl;
    delete[] m_iv;
    delete[] m_ciphertext;
    EVP_CIPHER_CTX_free(m_ctx);
    return -1;
}

/**
 * Error handling function for decryption
 * @param msg Error message
 * @return -1 to indicate an error
 */
int AesGcm::handleErrorDecrypt(const char *msg) {
    cerr << "AesGCM - Error during decryption: " << msg << endl;
    delete[] m_plaintext;
    EVP_CIPHER_CTX_free(m_ctx);
    return -1;
}

/**
 * Safely delete the IV from memory
 */
void AesGcm::cleanIV() {
    // Cleanse and delete the IV
    OPENSSL_cleanse(m_iv, m_iv_len);
    delete[] m_iv;
}

/**
 * Get function for the IV
 */
unsigned char *AesGcm::getIV() {
    return m_iv;
}

/**
 * Get function for the IV length
 */
int AesGcm::getIVLen() const {
    return m_iv_len;
}
