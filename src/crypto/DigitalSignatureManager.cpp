#include "DigitalSignatureManager.h"
#include <iostream>

using namespace std;

void DigitalSignatureManager::generateDS(unsigned char* input_buffer,
                                         long int input_buffer_size,
                                         unsigned char*& digital_signature,
                                         unsigned int& digital_signature_size,
                                         EVP_PKEY* private_key) {

    // Allocate memory for the digital signature buffer
    digital_signature = new unsigned char[EVP_PKEY_size(private_key)];

    // Create a new message digest context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // Initialize the signing process with SHA-256 algorithm
    EVP_SignInit(ctx, EVP_sha256());

    // Update the context with the input data
    EVP_SignUpdate(ctx, input_buffer, input_buffer_size);

    // Finalize the signing process and store the result in the digital signature buffer
    EVP_SignFinal(ctx, digital_signature, &digital_signature_size, private_key);

    // Free the message digest context
    EVP_MD_CTX_free(ctx);
}

bool DigitalSignatureManager::isDSverified(unsigned char* input_buffer,
                                           long int input_buffer_size,
                                           unsigned char* digital_signature,
                                           unsigned int digital_signature_size,
                                           EVP_PKEY* public_key) {

    // Create a new message digest context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // Initialize the verification process with SHA-256 algorithm
    EVP_VerifyInit(ctx, EVP_sha256());

    // Update the context with the input data
    EVP_VerifyUpdate(ctx, input_buffer, input_buffer_size);

    // Perform the verification and check the result
    int res = EVP_VerifyFinal(ctx, digital_signature, digital_signature_size, public_key);

    // Free the message digest context
    EVP_MD_CTX_free(ctx);

    // Check the verification result
    if (res != 1) {
        cerr << "DigitalSignatureManager - Failed to verify the digital signature" << endl;
        return false;
    }
    return true;
}