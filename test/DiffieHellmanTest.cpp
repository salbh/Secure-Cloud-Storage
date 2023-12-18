#include <cassert>
#include <openssl/dh.h>
#include "../src/crypto/DiffieHellman.h"
#include "iostream"

using namespace std;

void testGenerateLowLevelStructure() {
    DiffieHellman * dh_instance = new DiffieHellman();
    DH * dh = dh_instance->generateLowLevelStructure();
    assert(dh != nullptr);
    cout << "testGenerateLowLevelStructure() passed!" << endl;
    DH_free(dh);
    delete dh_instance;
}

void testLoadDHParameters() {
    DiffieHellman * dh_instance = new DiffieHellman();
    assert(dh_instance->getDhParameters() != nullptr);
    cout << "testLoadDHParameters() passed!" << endl;
    delete dh_instance;
}

void testGenerateEphemeralKey() {
    DiffieHellman * dh_instance = new DiffieHellman();
    EVP_PKEY *ephemeralKey = dh_instance->generateEphemeralKey();
    assert(ephemeralKey != nullptr);
    cout << "testGenerateEphemeralKey() passed!" << endl;
    EVP_PKEY_free(ephemeralKey);
    delete dh_instance;
}

int main() {
    testGenerateLowLevelStructure();
    testLoadDHParameters();
    testGenerateEphemeralKey();
    return 0;
}
