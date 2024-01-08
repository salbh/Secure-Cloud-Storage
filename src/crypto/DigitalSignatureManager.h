#ifndef SECURE_CLOUD_STORAGE_DIGITALSIGNATUREMANAGER_H
#define SECURE_CLOUD_STORAGE_DIGITALSIGNATUREMANAGER_H


#include <openssl/evp.h>

class DigitalSignatureManager {


public:
    void generateDS(unsigned char *input_buffer, long input_buffer_size, unsigned char *&digital_signature,
                    unsigned int &digital_signature_size, EVP_PKEY *private_key);

    bool isDSverified(unsigned char *input_buffer, long input_buffer_size, unsigned char *digital_signature,
                      unsigned int digital_signature_size, EVP_PKEY *public_key);
};


#endif //SECURE_CLOUD_STORAGE_DIGITALSIGNATUREMANAGER_H
