#ifndef SECURE_CLOUD_STORAGE_DIFFIEHELLMAN_H
#define SECURE_CLOUD_STORAGE_DIFFIEHELLMAN_H


#include <cstdint>

class DiffieHellman {
    // Diffie-Hellman parameters
    EVP_PKEY *m_dh_parameters;

public:
    DiffieHellman();
    DH * generateLowLevelStructure();
    void loadDHParameters(DH *pSt);
    EVP_PKEY * generateEphemeralKey();
    int serializeEphemeralKey(EVP_PKEY *ephemeral_key, uint8_t *&serialized_ephemeral_key,
                          int &serialized_ephemeral_key_size);
    EVP_PKEY *deserializeEphemeralKey(uint8_t *serialized_ephemeral_key, int serialized_ephemeral_key_size);
    int deriveSharedSecret(EVP_PKEY *own_ephemeral_key, EVP_PKEY *peer_ephemeral_key, unsigned char *&shared_secret,
                           size_t &shared_secret_size);
};


#endif //SECURE_CLOUD_STORAGE_DIFFIEHELLMAN_H
