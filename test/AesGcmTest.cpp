#include <iostream>
#include <cstring>
#include <cassert>
#include "AesGcm.h"

using namespace std;

void printHex(const unsigned char* data, int length) {
    for (int i = 0; i < length; ++i) {
        cout << hex << static_cast<int>(data[i]);
    }
    cout << dec << endl;
}

void testEncryptionAndDecryption() {
    const unsigned char key[] = "0123456789ABCDEF";  // 128-bit key
    AesGcm aesGcm(key);

    const char* plaintext = "Hello, AES-GCM!";
    int plaintext_len = strlen(plaintext);

    unsigned char* aad = nullptr;
    int aad_len = 0;

    unsigned char* ciphertext = nullptr;
    unsigned char tag[AesGcm::AES_TAG_LEN];

    int encrypted_len = aesGcm.encrypt((unsigned char*)plaintext, plaintext_len, aad, aad_len, ciphertext, tag);

    unsigned char* iv = aesGcm.getIV();

    unsigned char* decrypted_text = nullptr;
    int decrypted_len = aesGcm.decrypt(ciphertext, encrypted_len, aad, aad_len, iv, tag, decrypted_text);

    cout << "Decrypted text len: " << decrypted_len << endl;

    assert(plaintext_len == decrypted_len && "Decrypted length matches");
    assert(strcmp(plaintext, reinterpret_cast<const char*>(decrypted_text)) == 0 && "Decrypted text matches");

    cout << "Plaintext: " << plaintext << endl;
    cout << "Ciphertext: ";
    printHex(ciphertext, encrypted_len);

    cout << "Decrypted Text: " << reinterpret_cast<const char*>(decrypted_text) << endl;

    delete[] ciphertext;
    delete[] decrypted_text;
}

void testEncryptionErrorHandling() {
    const unsigned char key[] = "0123456789ABCDEF";  // 128-bit key
    AesGcm aesGcm(key);

    const char* plaintext = "Hello, AES-GCM!";
    int plaintext_len = strlen(plaintext);

    unsigned char* aad = nullptr;
    int aad_len = 0;

    unsigned char* ciphertext = nullptr;
    unsigned char tag[AesGcm::AES_TAG_LEN];

    int encrypted_len = aesGcm.encrypt(nullptr, plaintext_len, aad, aad_len, ciphertext, tag);

    assert(encrypted_len == -1 && "Encryption error detected");

    cout << "Ciphertext (Error Case): ";
    printHex(ciphertext, encrypted_len);

    delete[] ciphertext;
}

void testDecryptionErrorHandling() {
    const unsigned char key[] = "0123456789ABCDEF";  // 128-bit key
    AesGcm aesGcm(key);

    const char* plaintext = "Hello, AES-GCM!";
    int plaintext_len = strlen(plaintext);

    unsigned char* aad = nullptr;
    int aad_len = 0;

    unsigned char* ciphertext = nullptr;
    unsigned char tag[AesGcm::AES_TAG_LEN];

    int encrypted_len = aesGcm.encrypt(reinterpret_cast<unsigned char*>(const_cast<char*>(plaintext)),
                                       plaintext_len, aad, aad_len, ciphertext, tag);

    unsigned char* iv = aesGcm.getIV();
    unsigned char incorrect_tag[AesGcm::AES_TAG_LEN];
    memset(incorrect_tag, 0, AesGcm::AES_TAG_LEN);  // Incorrect tag

    unsigned char* decrypted_text = nullptr;
    int decrypted_len = aesGcm.decrypt(ciphertext, encrypted_len, aad, aad_len, iv, incorrect_tag, decrypted_text);

    assert(decrypted_len == -1 && "Decryption error detected");

    cout << "Ciphertext (Decryption Error Case): ";
    printHex(ciphertext, encrypted_len);

    delete[] ciphertext;
    delete[] decrypted_text;
}

int main() {
    cout << "Running Test: Encryption and Decryption" << endl;
    testEncryptionAndDecryption();

    cout << "Running Test: Encryption Error Handling" << endl;
    testEncryptionErrorHandling();

    cout << "Running Test: Decryption Error Handling" << endl;
    testDecryptionErrorHandling();

    return 0;
}
