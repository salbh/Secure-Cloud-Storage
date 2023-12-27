#include <iostream>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>


#include "CertificateManager.h"

using namespace std;


/**
 * Initial setting of the certificate manager instance pointer to null.
 * With this step the class is allowed to be allocated to memory.
 * Without it get the error to trying to access memory not allocated.
 */
CertificateManager* CertificateManager::m_certificate_manager_instance = nullptr;


/**
 * CertificateManager Constructor. Performs the following operations:
 * 1) Loads the CA Certificate from a file
 * 2) Loads the Certificate Revocation List (CRL) from a file
 * 3) Creates a new Certificate Store and stores the certificates loaded (CA and CRL)
 * 4) Frees the memory allocated for CA Certificate and CRL
 */
CertificateManager::CertificateManager() {

    //1)CA Certificate reading and loading
    //Allocates the X509 CA certificate structure and loads it from a PEM file
    X509* ca_certificate = loadCertificate(CA_CERTIFICATE_PATH);

    //2)CRL File (Certificate Revocation List) reading and loading
    //opening the Certificate Revocation List file and check the correctness
    FILE* crl_fp = fopen(CRL_PATH, "r");
    if (!crl_fp) {
        cerr << "CertificateManager - Failed to open the CRL file" << endl;
        return;
    }
    //Allocates the X509 Certificate Revocation List structure and loads it from a PEM file
    X509_CRL* crl = PEM_read_X509_CRL(crl_fp, NULL, NULL, NULL);

    //close the Certificate Revocation List file and check the correctness
    fclose(crl_fp);
    if (!crl) {
        cerr << "CertificateManager - Failed to load the CRL structure" << endl;
        return;
    }

    //3)Allocate a new Certificate Store and save the certificates loaded (certificate and CRL)
    //Allocates an empty store and (returns NULL if an error occurred)
    m_certificate_store = X509_STORE_new();
    if (!m_certificate_store) {
        cerr << "CertificateManager - Failed to create the store" << endl;
        return;
    }
    //Adds the CA certificate (trusted) to the store
    if (X509_STORE_add_cert(m_certificate_store, ca_certificate) != 1) {
        cerr << "CertificateManager - Failed to add CA certificate to the store" << endl;
        return;
    }
    //Adds the CRL (trusted) to the store
    if (X509_STORE_add_crl(m_certificate_store, crl) != 1) {
        cerr << "CertificateManager - Failed to add CRL to the store" << endl;
        return;
    }

    //Configures the store to check against the CRL every valid certificate before returning a successful validation
    if (X509_STORE_set_flags(m_certificate_store, X509_V_FLAG_CRL_CHECK) != 1) {
        cerr << "CertificateManager - Failed set the store flags" << endl;
        return;
    }

    //4)Free the memory allocated for the X.509 certificate and X.509 Certificate Revocation List (CRL) structures
    X509_free(ca_certificate);
    X509_CRL_free(crl);
}


/**
 * Function to load a certificate specified by the file path
 * @param certificate_path Path from which read the certificate location
 * @return
 */
X509 *CertificateManager::loadCertificate(const char* certificate_path) {
        //Opening the CA certificate file and check the correctness
        FILE* certificate_fp = fopen(certificate_path, "r");
        if (!certificate_fp) {
            cerr << "CertificateManager - Failed to open the certificate file" << endl;
            return nullptr;
        }

        //Allocates the X509 certificate structure and loads it from a PEM file
        X509* certificate = PEM_read_X509(certificate_fp, NULL, NULL, NULL);
        fclose(certificate_fp);
        if (!certificate) {
            cerr << "CertificateManager - Failed to load the certificate structure" << endl;
            return nullptr;
        }

        //Return the certificate loaded
        return certificate;
}


/**
 * Function to verify the received certificates
 * @param certificate Certificate to verify
 * @return
 */
bool CertificateManager::verifyCertificate(X509 *certificate) {

    //Allocates a new certificate-verification context
    X509_STORE_CTX* certificate_verification_ctx = X509_STORE_CTX_new();
    if (!certificate_verification_ctx) {
        cerr << "CertificateManager - Failed to create the certificate-verification context" << endl;
        return false;
    }

    //Initializes the certificate-verification context (context, store and certificate to verify)
    if (X509_STORE_CTX_init(certificate_verification_ctx, m_certificate_store, certificate,NULL) != 1) {
        cerr << "CertificateManager - Failed to initialize the certificate-verification context" << endl;
        return false;
    }

    //Verifies the certificate passed at initialization time
    if (X509_verify_cert(certificate_verification_ctx) != 1) {
        cerr << "CertificateManager - Certificate verification failed!" << endl;
        return false;
    }

    //Deallocates the certificate-verification context
    X509_STORE_CTX_free(certificate_verification_ctx);
    return true;
}


/**
 * Function to extract the public key from the certificate
 * @param certificate certificate from which extract the public key
 * @return
 */
EVP_PKEY *CertificateManager::getPublicKey(X509 *certificate) {
    //Extracts the public key from the certificate cert (It returns the EVP_PKEY structure representing
    //the public key, or NULL if an error occurs)
    EVP_PKEY* certificate_public_key = X509_get_pubkey(certificate);
    return certificate_public_key;
}


/**
 * Function to serializeLogoutMessage a certificate (when has to be sent)
 * @param certificate_to_serialize certificate to be serialized
 * @param certificate_pointer pointer to the certificate structure which has to be serialized
 * @param certificate_size_pointer pointer to the size value of the certificate (to be updated with the serialized size value)
 * @return 0 if the serialization was successful, -1 otherwise
 */
int CertificateManager::serializeCertificate(X509* certificate_to_serialize, uint8_t*& certificate_pointer, int& certificate_size_pointer) {

    // Create a BIO (memory-based I/O) object to store serialized data
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        cerr << "CertificateManager - Failed to create BIO" << endl;
        return -1;
    }

    // Write the X.509 certificate to the BIO in PEM format
    if (!PEM_write_bio_X509(bio, certificate_to_serialize)) {
        cerr << "CertificateManager - Failed to write the certificate in the BIO" << endl;
        BIO_free(bio);
        return -1;
    }

    // Determine the size of the serialized data in the BIO and update the certificate size variable
    certificate_size_pointer = BIO_pending(bio);

    // Allocate memory for the serialized certificate (array of uint8_t) and update the certificate pointer
    certificate_pointer = new uint8_t[certificate_size_pointer];

    // Check if the serialized data written in the BIO allocated memory was successful
    if (BIO_read(bio, certificate_pointer, certificate_size_pointer) != certificate_size_pointer) {
        cerr << "CertificateManager - Failed to read the serialized certificate" << endl;
        //Free the memory associated with the BIO
        BIO_free(bio);
        //Free the memory allocated for the serialized certificate
        delete[] certificate_pointer;
        return -1;
    }

    //Free the memory associated with the BIO
    BIO_free(bio);

    // Return success status
    return 0;
}


/**
 * Function to deserialize a certificate (when it is received)
 * @param certificate_pointer pointer to the certificate structure which has to be deserialized
 * @param certificate_size_pointer pointer to the size value of the certificate (to be updated with the deserialized size value)
 * @return the pointer to the deserialized certificate
 */
X509* CertificateManager::deserializeCertificate(uint8_t* certificate_pointer, int certificate_size_pointer) {

    // Create a BIO (memory-based I/O) object to read serialized data and deserialize it
    BIO* bio = BIO_new_mem_buf(certificate_pointer, certificate_size_pointer);
    if (!bio) {
        cerr << "CertificateManager - Failed to create BIO" << endl;
        return nullptr;  // nullptr indicates failure
    }

    // Initialize the pointer for the deserialized X.509 certificate
    X509* deserialized_certificate = nullptr;

    //Read the X.509 certificate from the BIO in PEM format
    deserialized_certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    // Check if the certificate deserialization was successful
    if (!deserialized_certificate) {
        cerr << "CertificateManager - Failed to deserialize the certificate" << endl;
        //Free the memory associated with the BIO
        BIO_free(bio);
        return nullptr;
    }

    //Free the memory associated with the BIO
    BIO_free(bio);

    // Return the pointer to the deserialized X.509 certificate
    return deserialized_certificate;
}


/**
 * CertificateManager Destructor. Free the memory for the allocated Certificate Store
 */
CertificateManager::~CertificateManager() {
    //Deallocates the Certificate Store
    X509_STORE_free(m_certificate_store);
}


/**
 * Function to deallocate the singleton from memory
 */
void CertificateManager::deleteInstance() {
    //Deletes the certificate manager instance pointer
    delete m_certificate_manager_instance;
    //Set the instance pointer to null in order to allocate again the singleton
    m_certificate_manager_instance = nullptr;
}
