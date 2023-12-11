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
};


#endif //SECURE_CLOUD_STORAGE_DIFFIEHELLMAN_H
