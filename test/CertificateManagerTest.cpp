#include <iostream>
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

X509* loadCertificateTest(CertificateManager* certificate_manager) {
    cout << "CertificateManagerTest - load certificate test " << endl;
    const char* certificate_filename = "../resources/certificates/Server_certificate.pem";
    X509* certificate = certificate_manager->loadCertificate(certificate_filename);
    assert(certificate != nullptr);
    cout << "+TEST OK+\n" << endl;
    return certificate;
}

void verifyCertificateTest(CertificateManager* certificate_manager, X509* certificate) {
    cout << "CertificateManagerTest - verify certificate test " << endl;
    assert(certificate_manager->verifyCertificate(certificate));
    cout << "+TEST OK+\n" << endl;
}

void getPublicKeyTest(CertificateManager* certificate_manager, X509* certificate) {
    cout << "CertificateManagerTest - get public key test " << endl;
    EVP_PKEY* public_key = certificate_manager->getPublicKey(certificate);
    //cout << "PUBLIC KEY : " << endl;
    //BIO_dump_fp(stdout, (const char*)public_key, 256);
    assert(public_key!= nullptr);
    cout << "+TEST OK+\n" << endl;
}

void serializeDeserializeCertificateTest(CertificateManager* certificate_manager, X509* certificate) {
    int serialized_certificate_size = 0;
    uint8_t* serialized_certificate = nullptr;

    cout << "CertificateManagerTest - Serialize certificate test " << endl;
    assert(certificate_manager->serializeCertificate(certificate, serialized_certificate, serialized_certificate_size) == 0);
    cout << "Serialized certificate size: " << serialized_certificate_size << endl;
    cout << "+TEST OK+\n" << endl;

    cout << "CertificateManagerTest - Deserialize certificate test " << endl;
    X509* deserialized_certificate =  certificate_manager->deserializeCertificate(serialized_certificate, serialized_certificate_size);
    assert(deserialized_certificate != nullptr);
    cout << "+TEST OK+\n" << endl;

}


int main() {
    cout<< "***TEST CERTIFICATE MANAGER***" << endl;

    //create Instance test(constructor)
    CertificateManager* certificate_manager = getInstanceTest();

    //load certificate test
    X509* certificate =  loadCertificateTest(certificate_manager);

    //verifyCertificate
    verifyCertificateTest(certificate_manager, certificate);

    //getPublicKey
    getPublicKeyTest(certificate_manager, certificate);

    //serializeLogoutMessage and deserialize certificate test
    serializeDeserializeCertificateTest(certificate_manager, certificate);

    //free memory and delete certificatre manager instance
    X509_free(certificate);
    CertificateManager::deleteInstance();

    return 0;

}