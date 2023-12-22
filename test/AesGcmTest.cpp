#include <iostream>
#include <cstring>
#include <cassert>
#include <iomanip>
#include "AesGcm.h"

using namespace std;

void testEncryptionAndDecryption() {
    const unsigned char key[] = "0123456789abcdef";
    AesGcm aesGcm(key);

    // Test data
    const char* plaintext = "Hello, this is a test!";
    const int plaintext_len = strlen(plaintext);

    const char* aad = "12";
    const int aad_len = strlen(aad);

    cout << "Original plaintext: " << plaintext << endl;
    cout << "Plaintext length: " << plaintext_len << endl;

    unsigned char* ciphertext = nullptr;
    unsigned char tag[AesGcm::AES_TAG_LEN];

    // Encrypt
    int ciphertext_len = aesGcm.encrypt(
            (unsigned char*)plaintext,
            plaintext_len,
            (unsigned char*)aad, aad_len,
            ciphertext,
            tag
    );
    assert(ciphertext_len > 0);

    cout << "\nCiphertext length: " << ciphertext_len << endl;

    // Get IV for decryption
    unsigned char* iv = aesGcm.getIV();
    int iv_len = aesGcm.getIVLen();
    cout << "IV length: " << iv_len << endl;

    // Print IV for debugging
    cout << "IV: ";
    for (int i = 0; i < iv_len; ++i) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(iv[i]) << " ";
    }
    cout << dec << endl;

    // Decrypt
    unsigned char* decryptedText = nullptr;
    int decrypted_len = aesGcm.decrypt(
            ciphertext, ciphertext_len,
            (unsigned char *) aad, aad_len,
            iv, tag,
            decryptedText
    );
    assert(decrypted_len == plaintext_len);

    cout << "\nDecrypted plaintext: " << reinterpret_cast<char*>(decryptedText) << endl;
    cout << "Decrypted plaintext length: " << decrypted_len << endl;

    // Verify the decrypted text
    assert(strcmp(plaintext, reinterpret_cast<char*>(decryptedText)) == 0);

    // Clean up
    delete[] ciphertext;
    delete[] decryptedText;

    cout << "\nTest Passed!" << endl;
}

int main() {
    // Run the tests
     testEncryptionAndDecryption();

    return 0;
}


