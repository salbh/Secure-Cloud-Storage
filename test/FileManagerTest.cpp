#include "FileManager.h"
#include "AesGcm.h"
#include <cassert>
#include <iostream>
#include <cstring>

using namespace std;

void testFileManager() {
    const char plaintext[] = "Hello, World!";
    auto len = static_cast<streamsize>(strlen(plaintext));

    cout << "Writing on test_1.txt file" << endl;
    FileManager fm_write("test_1.txt", FileManager::OpenMode::WRITE);
    fm_write.writeChunk(plaintext, len);

    // Destructor will be automatically called when fm_write goes out of scope

    auto fileData = new char[len];

    cout << "Reading from test_1.txt file" << endl;
    FileManager fm_read("test_1.txt", FileManager::OpenMode::READ);
    streamsize bytesRead = fm_read.readChunk(fileData, len);

    // Destructor will be automatically called when fm_read goes out of scope

    cout << "Data read from file: ";
    for (streamsize i = 0; i < bytesRead; ++i) {
        cout << fileData[i];
    }
    cout << "\n\n[+] Test Passed!" << endl;
    cout << "--------------------------------------------" << endl;

    delete[] fileData;
    // Delete the file
    remove("test_1.txt");
}

void testFileManagerWithEncryption() {
    const char key[] = "0123456789012345";

    // Test AesGcm encryption
    std::cout << "Testing AesGcm encryption..." << std::endl;
    AesGcm aesGcm(reinterpret_cast<const unsigned char*>(key));

    const char plaintext[] = "Hello, World!";
    const char aad[] = "AdditionalData";
    unsigned char* ciphertext;
    unsigned char tag[AesGcm::AES_TAG_LEN];
    int ciphertext_len = aesGcm.encrypt(
            reinterpret_cast<unsigned char*>(const_cast<char*>(plaintext)),
            strlen(plaintext),
            reinterpret_cast<unsigned char*>(const_cast<char*>(aad)),
            strlen(aad),
            ciphertext,
            tag
    );

    assert(ciphertext_len > 0);

    // Write the encrypted data to a file using FileManager
    std::cout << "Writing encrypted data to file..." << std::endl;
    FileManager fileManager("test_file.txt", FileManager::OpenMode::WRITE);
    fileManager.writeChunk(reinterpret_cast<const char*>(ciphertext), ciphertext_len);
    assert(fileManager.getFileSize() == 0);

    // Cleanup (optional)
    delete[] ciphertext;

    // Close the file
    fileManager.~FileManager();

    // Reopen the file in read mode
    std::cout << "Reopening file in read mode..." << std::endl;
    FileManager fileManagerRead("test_file.txt", FileManager::OpenMode::READ);

    // Read the encrypted data from the file
    std::cout << "Reading encrypted data from file..." << std::endl;
    char* encryptedData = new char[fileManagerRead.getFileSize()];
    fileManagerRead.readChunk(encryptedData, fileManagerRead.getFileSize());

    // Test AesGcm decryption
    std::cout << "Testing AesGcm decryption..." << std::endl;
    unsigned char* decryptedText;
    int decrypted_len = aesGcm.decrypt(
            reinterpret_cast<unsigned char*>(const_cast<char*>(encryptedData)),
            ciphertext_len,
            reinterpret_cast<unsigned char*>(const_cast<char*>(aad)),
            strlen(aad),
            aesGcm.getIV(),
            tag,
            decryptedText
    );

    assert(decrypted_len > 0);
    assert(strcmp(reinterpret_cast<char*>(decryptedText), plaintext) == 0);

    // Cleanup (optional)
    delete[] encryptedData;
    delete[] decryptedText;
    remove("test_file.txt");
}

int main() {
    // Run the tests

    testFileManager();

//    testFileManagerWithEncryption();

    return 0;
}


