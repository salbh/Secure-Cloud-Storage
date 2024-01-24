#include "FileManager.h"
#include "AesGcm.h"
#include <cassert>
#include <iostream>
#include <cstring>
#include "Config.h"

using namespace std;

void testReadAndWrite() {
    const char plaintext[] = "Hello, World!";
    auto plaintext_len = static_cast<streamsize>(strlen(plaintext));
    string file_path = "test_1.txt";

    // Write to file
    cout << "Writing on test_1.txt file" << endl;
    FileManager fm_write(file_path, FileManager::OpenMode::WRITE);
    int res = fm_write.writeChunk((uint8_t *) plaintext, plaintext_len);
    assert(res == 0);
    fm_write.initFileInfo(plaintext_len);
    assert(fm_write.getFileSize() == plaintext_len && fm_write.getChunksNum() == 1);
    // Close the file
    fm_write.closeFile();

    // Read from file
    auto fileData = new char[plaintext_len];
    cout << "Reading from test_1.txt file" << endl;
    FileManager fm_read("test_1.txt", FileManager::OpenMode::READ);
    streamsize file_size = fm_read.getFileSize();
    assert(file_size == plaintext_len);
    res = fm_read.readChunk(reinterpret_cast<uint8_t *>(fileData), file_size);
    assert(res == 0);

    cout << "Data read from file: ";
    for (const char *ptr = fileData; *ptr; ptr++) {
        cout << *ptr;
    }
    cout << "\n\n[+] Test Passed!" << endl;
    cout << "--------------------------------------------" << endl;

    delete[] fileData;
    // Delete the file
    remove("test_1.txt");
}

void testReadAndWriteChunks() {
    // Create a 10MB test file
    ofstream file("test_2.txt", ios::binary);
    assert(file.is_open());

    const streamsize MEGABYTE = 1024 * 1024;
    streamsize size = (10 * MEGABYTE) + (50 * 1024); // 10 MB size + 50 KB in last chunk

    // Write actual data to the file to achieve the desired size
    for (int i = 0; i < size; i++) {
        file.put(0);
    }
    file.close();

    // Open the file in read mode and init member variables
    FileManager fm_read("test_2.txt", FileManager::OpenMode::READ);
    // Check correct file size
    cout << "File size in bytes: " << fm_read.getFileSize() << endl;
    double file_size_MB = (double) fm_read.getFileSize() / (double) MEGABYTE;
    cout << "Number of MB: " << file_size_MB << endl;
    assert(file_size_MB > 10);
    // Check correct number of chunks
    streamsize chunksNum = fm_read.getChunksNum();
    cout << "Number of chunks: " << chunksNum << endl;
    assert(chunksNum == 11);
    // Check last chunk size
    streamsize lastChunkSize = fm_read.getLastChunkSize();
    cout << "Last chunk size in bytes: " << lastChunkSize << endl;
    assert(lastChunkSize == 50 * 1024);

    // Open another file in write mode to copy the content
    FileManager fm_write("test_2_copy.txt", FileManager::OpenMode::WRITE);
    streamsize chunk_size = Config::CHUNK_SIZE;
    auto *buffer = new char[chunk_size];

    // Define key and init AesGcm
    unsigned char key[] = "0123456789abcdef";
    AesGcm aesGcm = AesGcm(key);

    // Iterate over each chunk of data
    for (size_t i = 0; i < chunksNum; ++i) {
        if (i == chunksNum - 1) {
            chunk_size = lastChunkSize;
        }
        // Init buffers and parameters
        unsigned char *plaintext = nullptr;
        unsigned char *aad = nullptr;
        int aad_len = 0;
        unsigned char *ciphertext = nullptr;
        unsigned char *iv;
        unsigned char tag[Config::AES_TAG_LEN];
        int ciphertext_len;

        // Read chunk from file
        fm_read.readChunk(reinterpret_cast<uint8_t *>(buffer), chunk_size);
        // Encrypt chunk
        ciphertext_len = aesGcm.encrypt(reinterpret_cast<unsigned char *>(buffer),
                                        static_cast<int>(chunk_size),
                                        aad, aad_len, ciphertext, tag);

        iv = aesGcm.getIV();

        // Decrypt chunk
        aesGcm.decrypt(ciphertext, ciphertext_len, aad, aad_len, iv, tag, plaintext);
        // Write chunk to file
        fm_write.writeChunk(plaintext, chunk_size);

        delete[] plaintext;
        delete[] aad;
        delete[] ciphertext;
        delete[] iv;
    }
    delete[] buffer;

    // Open the 2 files
    ifstream file1("test_2.txt", ios::binary);
    ifstream file2("test_2_copy.txt", ios::binary);
    assert(file1 && file2 && "Failed to open files for comparison");
    // Compare file content
    char ch1, ch2;
    while (file1.get(ch1) && file2.get(ch2)) {
        assert(ch1 == ch2);
    }

    // Compare file size
    assert(FileManager::computeFileSize("test_2.txt") ==
           FileManager::computeFileSize("test_2_copy.txt"));

    file1.close();
    file2.close();

    cout << "\n[+] Test Passed!" << endl;
    cout << "--------------------------------------------" << endl;

    // Delete files
    remove("test_2.txt");
    remove("test_2_copy.txt");
}

void testIsStringValid() {
    // Valid input
    string validInput = "example123";
    cout << "Test valid string" << endl;
    assert(FileManager::isStringValid(validInput));

    // Valid input with special characters
    string specialCharsInput = "user@domain";
    cout << "\nTest valid string with special characters" << endl;
    assert(FileManager::isStringValid(specialCharsInput));

    // Valid input with special characters
    string specialCharsInvalidInput = "user@/*%";
    cout << "\nTest invalid string with special characters" << endl;
    assert(!FileManager::isStringValid(specialCharsInvalidInput));

    // Empty input
    string emptyInput;
    cout << "\nTest empty string" << endl;
    assert(!FileManager::isStringValid(emptyInput));

    // Input exceeding maximum length
    string longInput = "thisIsALongFileNameThatExceedsTheMaxLength";
    cout << "\nTest invalid string with too many characters" << endl;
    assert(!FileManager::isStringValid(longInput));

    // Input with reserved name
    string reservedNameInput1 = ".";
    cout << "\nTest invalid string with reserved name ." << endl;
    assert(!FileManager::isStringValid(reservedNameInput1));

    // Input with reserved name
    string reservedNameInput2 = "..";
    cout << "\nTest invalid string with reserved name .." << endl;
    assert(!FileManager::isStringValid(reservedNameInput2));

    cout << "\n[+] Test Passed!" << endl;
    cout << "--------------------------------------------" << endl;
}

int main() {

    cout << "\nRunning Test Scenario 1: \n" << endl;
    testReadAndWrite();

    cout << "\nRunning Test Scenario 2: \n" << endl;
    testReadAndWriteChunks();

    cout << "\nRunning Test Scenario 3: \n" << endl;
    testIsStringValid();

    return 0;
}





