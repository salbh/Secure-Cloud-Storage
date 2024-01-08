#include <cassert>
#include <openssl/rsa.h>
#include "../src/crypto/DigitalSignatureManager.h"
#include <iostream>

using namespace std;

void cleanupAndReportError(const char* errorMessage, EVP_PKEY* private_key = nullptr, EVP_PKEY* public_key = nullptr,
                           BIGNUM* e = nullptr) {
    cerr << errorMessage << endl;

    if (private_key != nullptr) {
        EVP_PKEY_free(private_key);
    }

    if (public_key != nullptr) {
        EVP_PKEY_free(public_key);
    }

    if (e != nullptr) {
        BN_free(e);
    }
}

void generateDSTest() {
    DigitalSignatureManager signatureManager;

    // Input data
    unsigned char input_buffer[] = "Hello, World!";
    long int input_buffer_size = sizeof(input_buffer);
    EVP_PKEY* private_key = EVP_PKEY_new();
    if (!private_key) {
        cerr << "generateDSTest() - Error generating Private key!" << endl;
        EVP_PKEY_free(private_key);
    }
    cout << "generateDSTest() - Private key generated!" << endl;

    RSA* rsa = RSA_new();

    // Set RSA key parameters
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);

    if (RSA_generate_key_ex(rsa, 4096, e, NULL) != 1) {
        cerr << "generateDSTest() - Error generating RSA key pair" << endl;
        EVP_PKEY_free(private_key);
        BN_free(e);
    }
    cout << "generateDSTest() - RSA key pair generated" << endl;
    // Set the private key
    if(!EVP_PKEY_assign_RSA(private_key, rsa)){
        cerr << "generateDSTest() - Error setting the Private key!" << endl;
        EVP_PKEY_free(private_key);
        BN_free(e);
    }

    // Variables to store the generated digital signature
    unsigned char* digital_signature = nullptr;
    unsigned int digital_signature_size = 0;

    // Generate digital signature
    signatureManager.generateDS(input_buffer, input_buffer_size, digital_signature, digital_signature_size, private_key);

    // Assert that digital signature is not null and size is greater than 0
    assert(digital_signature != nullptr);
    cout << "generateDSTest() - Digital Signature not null!" << endl;
    //cout << "generateDSTest() - Digital Signature Size: " << digital_signature_size << endl;
    assert(digital_signature_size > 0);
    cout << "generateDSTest() - Digital Signature greater than 0!" << endl;
    cout << "generateDSTest() passed!" << endl;

    // Clean up allocated memory
    delete[] digital_signature;
    EVP_PKEY_free(private_key);
    BN_free(e);
}

void isDSVerifiedTest(){
    DigitalSignatureManager signatureManager;

    RSA* rsa = RSA_new();
    // Set RSA key parameters
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);

    EVP_PKEY* private_key = EVP_PKEY_new();
    EVP_PKEY* public_key = EVP_PKEY_new();
    if (!private_key) {
        cleanupAndReportError("isDSVerifiedTest() - Error generating Private key!", private_key, public_key,
                              e);
    }
    cout << "isDSVerifiedTest() - Private key generated!" << endl;

    if (!public_key) {
        cleanupAndReportError("isDSVerifiedTest() - Error generating Public key!", private_key, public_key,
                              e);
    }
    cout << "isDSVerifiedTest() - Public key generated!" << endl;

    if (RSA_generate_key_ex(rsa, 4096, e, NULL) != 1) {
        cleanupAndReportError("isDSVerifiedTest() - Error generating RSA key pair!", private_key, public_key,
                              e);
        return;
    }
    cout << "isDSVerifiedTest() - RSA key pair generated" << endl;

    // Set the private key
    if(!EVP_PKEY_assign_RSA(private_key, rsa)){
        cleanupAndReportError("isDSVerifiedTest() - Error setting the Private key!", private_key, public_key,
                              e);
    }

    // Set the public key
    if(!EVP_PKEY_assign_RSA(public_key, EVP_PKEY_get1_RSA(private_key))){
        cleanupAndReportError("isDSVerifiedTest() - Error setting the Public key!", private_key, public_key,
                              e);
    }

    // Input data
    unsigned char input_buffer[] = "Hello, World!";
    long int input_buffer_size = sizeof(input_buffer);

    // Variables to store the generated digital signature
    unsigned char* digital_signature = nullptr;
    unsigned int digital_signature_size = 0;

    // Generate digital signature
    signatureManager.generateDS(input_buffer, input_buffer_size, digital_signature, digital_signature_size,
                                private_key);
    cout << "isDSVerifiedTest() - Digital Signature generated!" << endl;
    // Verify digital signature
    bool result = signatureManager.isDSverified(input_buffer, input_buffer_size, digital_signature,
                                                            digital_signature_size, public_key);
    cout << "isDSVerifiedTest() - Digital Signature verified!" << endl;
    // Assert that verification result is true
    assert(result);
    cout << "isDSVerifiedTest() passed!" << endl;
    // Clean up allocated memory
    delete[] digital_signature;
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    BN_free(e);
}

int main() {
    generateDSTest();
    isDSVerifiedTest();
    return 0;
}
