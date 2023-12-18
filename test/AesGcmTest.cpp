#include <iostream>
#include <cstring>
#include <cassert>
#include "AesGcm.h"

using namespace std;

// Test case for successful encryption and decryption
void testEncryptionAndDecryption() {
    const unsigned char key[] = "0123456789ABCDEF";  // 128-bit key
    AesGcm aesGcm(key);

    const char* plaintext = "Hello, AES-GCM!";
    int plaintext_len = strlen(plaintext);
    cout << "Plaintext len: " << plaintext_len << endl;

    unsigned char* aad = nullptr;
    int aad_len = 0;

    unsigned char* ciphertext = nullptr;
    unsigned char tag[AesGcm::AES_TAG_LEN];

    int encrypted_len = aesGcm.encrypt(reinterpret_cast<unsigned char*>(const_cast<char*>(plaintext)),
                                       plaintext_len, aad, aad_len, ciphertext, tag);

    unsigned char* iv = aesGcm.getIV();

    unsigned char* decrypted_text = nullptr;
    int decrypted_len = aesGcm.decrypt(ciphertext, encrypted_len, aad, aad_len, iv, tag, decrypted_text);

    cout << "Decrypted text len: " << decrypted_len << endl;

    assert(plaintext_len == decrypted_len && "Decrypted length matches");
    assert(std::strcmp(plaintext, reinterpret_cast<const char*>(decrypted_text)) == 0 && "Decrypted text matches");

    // Print obtained values
    cout << "Plaintext: " << plaintext << endl;
    cout << "Ciphertext: ";
    for (int i = 0; i < encrypted_len; ++i) {
        cout << hex << static_cast<int>(ciphertext[i]);
    }
    cout << dec << endl;

    cout << "Decrypted Text: " << reinterpret_cast<const char*>(decrypted_text) << endl;

    // Cleanup
    delete[] ciphertext;
    delete[] decrypted_text;
}

// Test case for handling encryption error
void testEncryptionErrorHandling() {
    // Arrange
    const unsigned char key[] = "0123456789ABCDEF";  // 128-bit key
    AesGcm aesGcm(key);

    const char* plaintext = "Hello, AES-GCM!";
    int plaintext_len = strlen(plaintext);

    unsigned char* aad = nullptr;
    int aad_len = 0;

    unsigned char* ciphertext = nullptr;
    unsigned char tag[AesGcm::AES_TAG_LEN];

    // Force an error by providing a null pointer for plaintext
    int encrypted_len = aesGcm.encrypt(nullptr, plaintext_len, aad, aad_len, ciphertext, tag);

    // Assert
    assert(encrypted_len == -1 && "Encryption error detected");

    // Print obtained values
    cout << "Ciphertext (Error Case): ";
    for (int i = 0; i < encrypted_len; ++i) {
        cout << hex << static_cast<int>(ciphertext[i]);
    }
    cout << dec << endl;

    // Cleanup (if needed)
    // No need to cleanup as the encryption failed

    // Note: You can add more error scenarios as needed
}

// Test case for handling decryption error
void testDecryptionErrorHandling() {
    // Arrange
    const unsigned char key[] = "0123456789ABCDEF";  // 128-bit key
    AesGcm aesGcm(key);

    const char* plaintext = "Hello, AES-GCM!";
    int plaintext_len = strlen(plaintext);

    unsigned char* aad = nullptr;
    int aad_len = 0;

    unsigned char* ciphertext = nullptr;
    unsigned char tag[AesGcm::AES_TAG_LEN];

    // Encrypt the plaintext
    int encrypted_len = aesGcm.encrypt(reinterpret_cast<unsigned char*>(const_cast<char*>(plaintext)),
                                       plaintext_len, aad, aad_len, ciphertext, tag);

    // Introduce an error by providing an incorrect tag during decryption
    unsigned char* iv = aesGcm.getIV();
    unsigned char incorrect_tag[AesGcm::AES_TAG_LEN];
    memset(incorrect_tag, 0, AesGcm::AES_TAG_LEN);  // Incorrect tag

    unsigned char* decrypted_text = nullptr;
    int decrypted_len = aesGcm.decrypt(ciphertext, encrypted_len, aad, aad_len, iv, incorrect_tag, decrypted_text);

    // Assert
    assert(decrypted_len == -1 && "Decryption error detected");

    // Print obtained values
    cout << "Ciphertext (Decryption Error Case): ";
    for (int i = 0; i < encrypted_len; ++i) {
        cout << hex << static_cast<int>(ciphertext[i]);
    }
    cout << dec << endl;

    // Cleanup
//    delete[] ciphertext;
    // Note: No need to cleanup decrypted_text, as decryption failed
}

int main() {
    // Run the test cases
    cout << "Running Test: Encryption and Decryption" << endl;
    testEncryptionAndDecryption();

    cout << "Running Test: Encryption Error Handling" << endl;
    testEncryptionErrorHandling();

    cout << "Running Test: Decryption Error Handling" << endl;
    testDecryptionErrorHandling();

    // Add more test cases as needed

    return 0;
}
