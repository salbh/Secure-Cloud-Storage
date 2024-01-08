#include <cassert>
#include <iostream>
#include "Hash.h"

using namespace std;

void generateSHA256Test() {
    Hash hash;

    // Input data
    unsigned char input_buffer[] = "Hello, World!";
    size_t input_buffer_size = sizeof(input_buffer);

    // Variables to store the generated SHA-256 digest
    unsigned char* digest = nullptr;
    unsigned int digest_size = 0;

    // Generate SHA-256 digest
    hash.generateSHA256(input_buffer, input_buffer_size, digest, digest_size);

    // Assert that the digest is not null and size is greater than 0
    assert(digest != nullptr);
    cout << "generateSHA256Test() - Digest not null!" << endl;
    assert(digest_size > 0);
    cout << "generateSHA256Test() - Digest size greater than 0!" << endl;
    cout << "generateSHA256Test() passed!" << endl;

    // Clean up allocated memory
    delete[] digest;
}

int main() {
    generateSHA256Test();
    return 0;
}

