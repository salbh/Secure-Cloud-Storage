#include <iostream>
#include <string>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <vector>

#include "CertificateManager.h"

using namespace std;

/**
 * Program to generate users public keys extracted from the users certificates
 */
int main() {

    cout<< "*************************************\n"
           "*** PUBLIC KEY EXTRACTION PROGRAM ***\n"
           "*************************************\n" << endl;

    //List of certificate names
    std::vector<std::string> certificate_name_list = {"Francesco", "Luca", "Salvatore"};

    // Iterate through the list
    for (const std::string& name : certificate_name_list) { //iterate the list storing in a constant string "name"
        cout << "**Public Key Creation for " << name << "**" << endl;

        // Construct the certificate filename
        std::string certificate_filename_string = "../resources/certificates/" + name + "_cert.pem";
        // Convert to const char*
        const char* certificate_filename = certificate_filename_string.c_str();

        // Load the current certificate
        CertificateManager* certificate_store = CertificateManager::getInstance();
        X509* certificate = certificate_store->loadCertificate(certificate_filename);

        // Extract the public key from the certificate
        EVP_PKEY* public_key = certificate_store->getPublicKey(certificate);
        cout << "**Public key Extracted successfully**" << endl;

        // Save the public key in a file
        string public_key_filename_string = "../resources/public_keys/" + name + "_key.pem";
        BIO *bio = BIO_new_file(public_key_filename_string.c_str(), "w");
        PEM_write_bio_PUBKEY(bio, public_key);
        cout << "**Created Public key: " << name << "_key.pem" << "**\n" << endl;

        // Free resources
        BIO_free(bio);
        EVP_PKEY_free(public_key);
    }

    return 0;
}
