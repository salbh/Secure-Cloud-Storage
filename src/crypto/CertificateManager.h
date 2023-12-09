#ifndef SECURE_CLOUD_STORAGE_CERTIFICATEMANAGER_H
#define SECURE_CLOUD_STORAGE_CERTIFICATEMANAGER_H

#include <string>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

using namespace std;


class CertificateManager {
    static X509_STORE* m_certificate_store;

    const char* CA_CERTIFICATE_PATH = "resources/certificates/CA_certificate.pem";
    const char* CRL_PATH = "resources/certificates/CA_crl.pem";

public:
    static X509* loadCertificate(const char* certificate_path);
    static bool verifyCertificate(X509* certificate);
    static EVP_PKEY* getPublicKey(X509* certificate);

    static void deleteInstance();


private:
    static CertificateManager* m_certificate_manager_instance;

    //Function to manage the singleton (check and allocate the singleton class)
    static CertificateManager& createInstance() {
        if(!m_certificate_manager_instance) {
            m_certificate_manager_instance = new CertificateManager();
        }
        return *m_certificate_manager_instance;
    }

    CertificateManager();
    ~CertificateManager();


};


#endif //SECURE_CLOUD_STORAGE_CERTIFICATEMANAGER_H
