#include <iostream>
#include <string>
#include <vector>
#include <openssl/pem.h>
#include <cassert>

#include "../src/crypto/CertificateManager.h"

using namespace std;


CertificateManager* getInstanceTest() {
    cout << "CertificateManagerTest - get instance test " << endl;
    CertificateManager* certificate_manager = CertificateManager::getInstance();
    assert(certificate_manager != nullptr);
    cout << "+TEST OK+\n" << endl;
    return certificate_manager;
}

X509* loadCertificateTest(CertificateManager* certificate_manager, const char* certificate_filename) {
    cout << "CertificateManagerTest - load certificate test " << endl;
    X509* certificate = certificate_manager->loadCertificate(certificate_filename);
    assert(certificate != nullptr);
    cout << "+TEST OK+" << endl;
    return certificate;
}

void verifyCertificateTest(CertificateManager* certificate_manager, X509* certificate) {
    cout << "CertificateManagerTest - verify certificate test " << endl;
    assert(certificate_manager->verifyCertificate(certificate));
    cout << "+TEST OK+" << endl;
}

void getPublicKeyTest(CertificateManager* certificate_manager, X509* certificate) {
    cout << "CertificateManagerTest - get public key test " << endl;
    EVP_PKEY* public_key = certificate_manager->getPublicKey(certificate);
    assert(public_key!= nullptr);
    cout << "+TEST OK+" << endl;
}

void serializeDeserializeCertificateTest(CertificateManager* certificate_manager, X509* certificate) {
    int serialized_certificate_size = 0;
    uint8_t* serialized_certificate = nullptr;

    cout << "CertificateManagerTest - Serialize certificate test " << endl;
    assert(certificate_manager->serializeCertificate(certificate, serialized_certificate, serialized_certificate_size) == 0);
    cout << "Serialized certificate size: " << serialized_certificate_size << endl;
    cout << "+TEST OK+" << endl;

    cout << "CertificateManagerTest - Deserialize certificate test " << endl;
    X509* deserialized_certificate =  certificate_manager->deserializeCertificate(serialized_certificate, serialized_certificate_size);
    assert(deserialized_certificate != nullptr);
    cout << "+TEST OK+\n" << endl;

}


int main() {
    cout<< "********************************\n"
           "*** CERTIFICATE MANAGER TEST ***\n"
           "********************************\n" << endl;

    //create Instance test(constructor)
    CertificateManager* certificate_manager = getInstanceTest();

    //Make the tests on all the certificates

    //List of certificate names
    std::vector<std::string> certificate_name_list = {"Francesco", "Luca", "Salvatore", "Server"};

    // Iterate through the list
    for (const std::string& name : certificate_name_list) { //iterate the list storing in a constant string "name"
        cout << "**Tests for " << name << " Certificate **" << endl;

        // Construct the certificate filename
        std::string certificate_filename_string = "../resources/certificates/" + name + "_cert.pem";
        // Convert to const char*
        const char* certificate_filename = certificate_filename_string.c_str();

        //load certificate test
        X509* certificate =  loadCertificateTest(certificate_manager, certificate_filename);

        //verifyCertificate
        verifyCertificateTest(certificate_manager, certificate);

        //getPublicKey
        getPublicKeyTest(certificate_manager, certificate);

        //serialize and deserialize certificate test
        serializeDeserializeCertificateTest(certificate_manager, certificate);

        //free memory and delete certificate manager instance
        X509_free(certificate);
    }

    //delete the certificate manager instance
    CertificateManager::deleteInstance();
    cout << "+ALL TESTS PASSED+" << endl;

    return 0;

}