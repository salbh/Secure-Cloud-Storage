#ifndef SECURE_CLOUD_STORAGE_DIFFIEHELLMAN_H
#define SECURE_CLOUD_STORAGE_DIFFIEHELLMAN_H


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
};


#endif //SECURE_CLOUD_STORAGE_DIFFIEHELLMAN_H
