#ifndef SECURE_CLOUD_STORAGE_CERTIFICATEMANAGER_H
#define SECURE_CLOUD_STORAGE_CERTIFICATEMANAGER_H

#include <string>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

using namespace std;


class CertificateManager {
private:
    X509_STORE* m_certificate_store;
    static CertificateManager* m_certificate_manager_instance;

    const char* CA_CERTIFICATE_PATH = "../resources/certificates/CA_cert.pem";
    const char* CRL_PATH = "../resources/certificates/CA_crl.pem";

public:
    CertificateManager();
    ~CertificateManager();

    X509* loadCertificate(const char* certificate_path);
    bool verifyCertificate(X509* certificate);
    EVP_PKEY* getPublicKey(X509* certificate);
    int serializeCertificate(X509 *certificate, uint8_t *&certificate_pointer, int &certificate_size_pointer);
    X509* deserializeCertificate(uint8_t* certificate_pointer, int certificate_size_pointer);

    static void deleteInstance();

    //Function to manage the singleton (check and allocate the singleton class)
    static CertificateManager* getInstance() {
        if(!m_certificate_manager_instance) {
            m_certificate_manager_instance = new CertificateManager();
        }
        return m_certificate_manager_instance;
    }

};


#endif //SECURE_CLOUD_STORAGE_CERTIFICATEMANAGER_H
