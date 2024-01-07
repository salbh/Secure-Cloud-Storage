#include <iostream>
#include <cstring>
#include <cassert>
#include <iomanip>
#include "AesGcm.h"
#include "Config.h"

using namespace std;

// Init for test 1 (Non-empty plaintext and AAD)
void initializeTestScenario1(const char *&plaintext, int &plaintext_len,
                             const char *&aad, int &aad_len) {
    plaintext = "Hello, this is a test!";
    plaintext_len = strlen(plaintext);
    aad = "12";
    aad_len = strlen(aad);
}

// Init for test 2 (Non-empty plaintext and empty AAD)
void initializeTestScenario2(const char *&plaintext, int &plaintext_len,
                             const char *&aad, int &aad_len) {
    plaintext = "Hello, this is a test!";
    plaintext_len = strlen(plaintext);
    aad = "";
    aad_len = 0;
}

// Init for test 3 (Empty plaintext and non-empty AAD)
void initializeTestScenario3(const char *&plaintext, int &plaintext_len,
                             const char *&aad, int &aad_len) {
    plaintext = "";
    plaintext_len = 0;
    aad = "123";
    aad_len = strlen(aad);
}

// Init for test 4 (Empty plaintext and empty AAD)
void initializeTestScenario4(const char *&plaintext, int &plaintext_len,
                             const char *&aad, int &aad_len) {
    plaintext = "";
    plaintext_len = 0;
    aad = "";
    aad_len = 0;
}

// Init for test 5 (Non-empty plaintext but wrong AAD to the decrypt function)
void initializeTestScenario5(const char *&plaintext, int &plaintext_len,
                             const char *&aad, int &aad_len) {
    plaintext = "Hello, this is a test!";
    plaintext_len = strlen(plaintext);
    aad = "1234";
    aad_len = strlen(aad);
}

void testEncryptionAndDecryption(AesGcm &aesGcm, const char *plaintext, int plaintext_len,
                                 const char *aad, int aad_len, uint8_t test_number) {

    cout << "Original plaintext: " << plaintext << endl;
    cout << "Plaintext length: " << plaintext_len << endl;

    unsigned char* ciphertext = nullptr;
    unsigned char tag[Config::AES_TAG_LEN];

    // Encrypt
    int ciphertext_len = aesGcm.encrypt(
            (unsigned char *) plaintext,
            plaintext_len,
            (unsigned char *) aad, aad_len,
            ciphertext,
            tag
    );
    if (test_number == 3 or test_number == 4) {
        assert(ciphertext_len == 0);
    } else {
        assert(ciphertext_len > 0);
        assert(ciphertext_len == plaintext_len);
    }

    cout << "\nCiphertext length: " << ciphertext_len << endl;

    // Get IV for decryption
    unsigned char *iv = aesGcm.getIV();
    int iv_len = aesGcm.getIVLen();
    cout << "IV length: " << iv_len << endl;

    // Print IV for debugging
    cout << "IV: ";
    for (int i = 0; i < iv_len; ++i) {
        // Print the current byte of the IV in hex format, with a width of 2 characters,
        // leading zeros if needed and a space after each byte.
        cout << hex << setw(2) << setfill('0') << static_cast<int>(iv[i]) << " ";
    }
    // Set the stream's basefield flag back to decimal to avoid affecting subsequent output
    cout << dec << endl;

    if (test_number == 5) {
        aad = "2222";
    }

    // Decrypt
    unsigned char *decryptedText = nullptr;
    int decrypted_len = aesGcm.decrypt(
            ciphertext, ciphertext_len,
            (unsigned char *) aad, aad_len,
            iv, tag,
            decryptedText
    );

    if (test_number == 5) {
        assert(decrypted_len != plaintext_len);
        assert(decrypted_len == -1);
    } else {
        assert(decrypted_len == plaintext_len);
    }

    cout << endl;
    if (decrypted_len > 0) {
        cout << "Decrypted plaintext: " << reinterpret_cast<char *>(decryptedText) << endl;
    }
    cout << "Decrypted plaintext length: " << decrypted_len << endl;

    if (plaintext_len != 0 && test_number != 5) {
        // Verify the decrypted text
        assert(strcmp(plaintext, reinterpret_cast<char *>(decryptedText)) == 0);
    }
    // Clean up
    delete[] ciphertext;

    cout << "\n[+] Test Passed!" << endl;
    cout << "--------------------------------------------" << endl;
}

int main() {
    const unsigned char key[] = "0123456789abcdef";
    AesGcm aesGcm = AesGcm(key);

    const char *plaintext;
    int plaintext_len;
    const char *aad;
    int aad_len;

    // Init for test 1 (Non-empty plaintext and AAD)
    initializeTestScenario1(plaintext, plaintext_len, aad, aad_len);
    cout << "\nRunning Test Scenario 1: \n" << endl;
    testEncryptionAndDecryption(aesGcm, plaintext, plaintext_len,
                                aad, aad_len, 1);

    // Init for test 2 (Non-empty plaintext and empty AAD)
    initializeTestScenario2(plaintext, plaintext_len, aad, aad_len);
    cout << "Running Test Scenario 2: \n" << endl;
    testEncryptionAndDecryption(aesGcm, plaintext, plaintext_len,
                                aad, aad_len, 2);

    // Init for test 3 (Empty plaintext and non-empty AAD)
    initializeTestScenario3(plaintext, plaintext_len, aad, aad_len);
    cout << "Running Test Scenario 3: \n" << endl;
    testEncryptionAndDecryption(aesGcm, plaintext, plaintext_len,
                                aad, aad_len, 3);

    // Init for test 4 (Empty plaintext and empty AAD)
    initializeTestScenario4(plaintext, plaintext_len, aad, aad_len);
    cout << "Running Test Scenario 4: \n" << endl;
    testEncryptionAndDecryption(aesGcm, plaintext, plaintext_len,
                                aad, aad_len, 4);

    // Init for test 5 (Non-empty plaintext but wrong AAD to the decrypt function)
    initializeTestScenario5(plaintext, plaintext_len, aad, aad_len);
    cout << "Running Test Scenario 5 (wrong AAD): \n" << endl;
    testEncryptionAndDecryption(aesGcm, plaintext, plaintext_len,
                                aad, aad_len, 5);

    return 0;
}


