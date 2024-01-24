#include <cassert>
#include <openssl/dh.h>
#include <cstring>
#include "../src/crypto/DiffieHellman.h"
#include "iostream"

using namespace std;

void GenerateLowLevelStructureTest() {
    DiffieHellman * dh_instance = new DiffieHellman();
    DH * dh = dh_instance->generateLowLevelStructure();
    assert(dh != nullptr);
    cout << "GenerateLowLevelStructureTest() passed!" << endl;
    DH_free(dh);
    delete dh_instance;
}

void loadDHParametersTest() {
    DiffieHellman * dh_instance = new DiffieHellman();
    assert(dh_instance->getDhParameters() != nullptr);
    cout << "loadDHParametersTest() passed!" << endl;
    delete dh_instance;
}

void generateEphemeralKeyTest() {
    DiffieHellman * dh_instance = new DiffieHellman();
    EVP_PKEY *ephemeralKey = dh_instance->generateEphemeralKey();
    assert(ephemeralKey != nullptr);
    cout << "generateEphemeralKeyTest() passed!" << endl;
    EVP_PKEY_free(ephemeralKey);
    delete dh_instance;
}

void serializeEphemeralKeyTest() {
    DiffieHellman * dh_instance = new DiffieHellman();
    EVP_PKEY *ephemeralKey = dh_instance->generateEphemeralKey();
    uint8_t* serialized_ephemeral_key = nullptr;
    int serialized_ephemeral_key_size = 0;
    int result = dh_instance->serializeEphemeralKey(ephemeralKey, serialized_ephemeral_key,
                                                    serialized_ephemeral_key_size);
    // Print the value returned by the serializeEphemeralKey to detect eventual errors correctly
    cout << "serializeEphemeralKey() result: " << result << endl;
    // Check if the ephemeral was serialized
    assert(result == 0);
    assert(serialized_ephemeral_key != nullptr);
    assert(serialized_ephemeral_key_size != -1);
    cout << "serializeEphemeralKeyTest() passed!" << endl;
    delete[] serialized_ephemeral_key;
    serialized_ephemeral_key_size = -1;
    EVP_PKEY_free(ephemeralKey);
    delete dh_instance;
}

void deserializeEphemeralKeyTest() {
    DiffieHellman * dh_instance = new DiffieHellman();
    EVP_PKEY *ephemeral_key = dh_instance->generateEphemeralKey();
    uint8_t* serialized_ephemeral_key = nullptr;
    int serialized_ephemeral_key_size = -1;
    dh_instance->serializeEphemeralKey(ephemeral_key, serialized_ephemeral_key,
                                       serialized_ephemeral_key_size);
    EVP_PKEY* deserialized_ephemeral_key = dh_instance->deserializeEphemeralKey(serialized_ephemeral_key,
                                                                      serialized_ephemeral_key_size);
    assert(EVP_PKEY_cmp(ephemeral_key, deserialized_ephemeral_key) == 1);
    cout << "deserializeEphemeralKeyTest() passed!" << endl;

    delete[] serialized_ephemeral_key;
    serialized_ephemeral_key_size = -1;
    EVP_PKEY_free(ephemeral_key);
    EVP_PKEY_free(deserialized_ephemeral_key);
    delete dh_instance;
}

void deriveSharedSecretTest() {
    DiffieHellman * dh_instance_1 = new DiffieHellman();
    DiffieHellman * dh_instance_2 = new DiffieHellman();
    EVP_PKEY *ephemeral_key_1 = dh_instance_1->generateEphemeralKey();
    EVP_PKEY *ephemeral_key_2 = dh_instance_2->generateEphemeralKey();

    unsigned char *shared_secret_1, *shared_secret_2;
    size_t shared_secret_size_1, shared_secret_size_2;

    dh_instance_1->deriveSharedSecret(ephemeral_key_1, ephemeral_key_2, shared_secret_1, shared_secret_size_1);
    dh_instance_2->deriveSharedSecret(ephemeral_key_2, ephemeral_key_1, shared_secret_2, shared_secret_size_2);

    // cout << "deriveSharedSecretTest(): shared_secret_size_1 = " << shared_secret_size_1
    // << " and shared_secret_size_2 = " << shared_secret_size_2 << endl;
    assert(shared_secret_size_1 == shared_secret_size_2);
    cout << "deriveSharedSecretTest(): the shared secret size is equal between the client and the server!" << endl;
    // cout << "deriveSharedSecretTest(): shared_secret_1 = " << shared_secret_1
    // << " and shared_secret_2 = " << shared_secret_2 << endl;
    assert(memcmp(shared_secret_1, shared_secret_2, shared_secret_size_1) == 0);
    cout << "deriveSharedSecretTest(): the shared secret is equal between the client and the server!" << endl;
    cout << "deriveSharedSecretTest() passed!" << endl;

    EVP_PKEY_free(ephemeral_key_1);
    EVP_PKEY_free(ephemeral_key_2);
    delete dh_instance_1;
    delete dh_instance_2;
}

int main() {
    GenerateLowLevelStructureTest();
    loadDHParametersTest();
    generateEphemeralKeyTest();
    serializeEphemeralKeyTest();
    deserializeEphemeralKeyTest();
    deriveSharedSecretTest();
    return 0;
}
