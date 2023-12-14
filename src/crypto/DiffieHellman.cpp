#include <iostream>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "DiffieHellman.h"

using namespace std;

// DiffieHellman class constructor
DiffieHellman::DiffieHellman() {
    DH* dh_structure = generateLowLevelStructure();
    loadDHParameters(dh_structure);
}

// Create a new low-level DH structure and sets its parameters using predefined values
DH * DiffieHellman::generateLowLevelStructure() {
        // Static DH parameters (p and g values)
        static unsigned char dhp_2048[] = {
                0xE0, 0x08, 0xA7, 0xD2, 0x43, 0xEF, 0x5A, 0x16, 0x4B, 0xBC,
                0xCB, 0xB2, 0x8B, 0x37, 0x09, 0xBD, 0xC2, 0x37, 0x35, 0x86,
                0x69, 0x40, 0x40, 0x03, 0x2E, 0x71, 0xA8, 0xD4, 0x2C, 0xF1,
                0x71, 0x4E, 0x04, 0x54, 0x81, 0x8E, 0x48, 0xC8, 0xA9, 0x2D,
                0x1E, 0x82, 0x6E, 0x94, 0xF5, 0x1C, 0xA4, 0xD4, 0xF8, 0xC5,
                0x5C, 0xC6, 0x49, 0x2D, 0x49, 0x94, 0x02, 0x00, 0x3C, 0x19,
                0x2A, 0xD3, 0x16, 0xA4, 0x1C, 0x69, 0x61, 0x01, 0xAC, 0x8F,
                0x04, 0x2F, 0x33, 0xE3, 0x5E, 0x5A, 0x5C, 0x93, 0xA0, 0x31,
                0x7A, 0xF8, 0x04, 0x7C, 0x30, 0x8D, 0x17, 0xA9, 0xDC, 0xA0,
                0xB7, 0x95, 0x41, 0x4F, 0xD2, 0x6E, 0xD7, 0xE6, 0xE6, 0x4C,
                0x5F, 0x63, 0xC3, 0x04, 0x8B, 0xBA, 0x4B, 0x90, 0x47, 0x7D,
                0x02, 0x02, 0xF3, 0xB0, 0x6D, 0xDA, 0xCC, 0x72, 0x76, 0x18,
                0x30, 0x97, 0x49, 0x72, 0x24, 0x6F, 0xF7, 0x17, 0xB1, 0xDA,
                0x75, 0x9F, 0x6C, 0x6F, 0xD6, 0x35, 0x55, 0x17, 0x42, 0xC0,
                0x6B, 0x36, 0x07, 0x5C, 0xD7, 0x7D, 0x0C, 0x4F, 0xE5, 0x46,
                0x8E, 0x87, 0x53, 0x57, 0xC6, 0xE6, 0xE0, 0x9F, 0xBF, 0xCB,
                0xAA, 0xDA, 0x27, 0x87, 0x23, 0xF3, 0x79, 0xDF, 0x06, 0x5C,
                0x9A, 0xE4, 0x75, 0x8A, 0x42, 0x47, 0xE6, 0x9B, 0x5E, 0x0B,
                0xA6, 0x97, 0x76, 0xE0, 0xB2, 0x04, 0xB8, 0xE5, 0x0D, 0x84,
                0xCD, 0x68, 0xB6, 0x51, 0x20, 0xA4, 0x88, 0x3F, 0x28, 0x84,
                0x25, 0xA3, 0x53, 0x55, 0x18, 0x8A, 0xA0, 0x5D, 0x74, 0x3C,
                0xDB, 0x52, 0x0A, 0xCA, 0xB9, 0xDE, 0xC1, 0x3B, 0xC1, 0x6B,
                0x77, 0x4D, 0x24, 0xDB, 0x1E, 0x3D, 0xBD, 0x70, 0x37, 0xF9,
                0x9D, 0x27, 0x53, 0x63, 0x06, 0xDB, 0xB1, 0xD2, 0xB5, 0x3E,
                0x88, 0x14, 0xEA, 0xE4, 0x30, 0x03, 0xA0, 0x03, 0x0C, 0x13,
                0xE6, 0xCB, 0x9A, 0x4A, 0x5A, 0x1B
        };
        static unsigned char dhg_2048[] = {
                0x02
        };

        // Create a new DH structure
        DH *dh_structure = DH_new();
        BIGNUM *p, *g;

        if (dh_structure == NULL) {
            cerr << "DiffieHellman - Error in creating the DH structure" << endl;
            return nullptr;
        }
        p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
        g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);

        // Set DH parameters (p, q, and g) for the DH structure
        if (p == NULL || g == NULL || !DH_set0_pqg(dh_structure, p, NULL, g)) {
            cerr << "DiffieHellman - Error during the setting of the DH parameters" << endl;
            DH_free(dh_structure);
            BN_free(p);
            BN_free(g);
            return nullptr;
        }
        return dh_structure;
}

/**
 * Copy the generated standard parameters into an EVP_PKEY structure
 * @param dh_structure DH structure containing the parameters to be copied
 */
void DiffieHellman::loadDHParameters(DH *dh_structure) {
    // Create a new EVP_PKEY structure for holding DH parameters
    if (NULL == (m_dh_parameters = EVP_PKEY_new())) {
        cerr << "DiffieHellman - Error in creating the EVP_PKEY structure for DH parameters" << endl;
    }

    // Set the DH parameters in the EVP_PKEY structure
    if (1 != EVP_PKEY_set1_DH(m_dh_parameters, dh_structure)) {
        cerr << "DiffieHellman - Error during the setting of the DH parameters in EVP_PKEY structure" << endl;
    }
    // Free the memory associated with the original DH structure
    DH_free(dh_structure);
}

// Generates an ephemeral key pair for Diffie-Hellman key exchange
EVP_PKEY * DiffieHellman::generateEphemeralKey() {
    // Create context for the key generation
    EVP_PKEY_CTX *dh_context;
    if(!(dh_context = EVP_PKEY_CTX_new(m_dh_parameters, NULL))) {
        cerr << "DiffieHellman - Error in creating the key generation context" << endl;
    }
    // Generate a new key
    EVP_PKEY *dh_ephemeral_key = NULL;
    if(1 != EVP_PKEY_keygen_init(dh_context)){
        cerr << "DiffieHellman - Error during the initialization of the key generation" << endl;
    }
    if(1 != EVP_PKEY_keygen(dh_context, &dh_ephemeral_key)) {
        cerr << "DiffieHellman - Error in generating the ephemeral key" << endl;
    }
    // Cleanup the context
    EVP_PKEY_CTX_free(dh_context);
    return dh_ephemeral_key;
}

/**
 * Serializes the provided ephemeral key into PEM format.
 * @param ephemeral_key The ephemeral key to be serialized (EVP_PKEY structure)
 * @param serialized_ephemeral_key The pointer to the buffer that will store the serialized key
 * @param serialized_ephemeral_key_size The integer reference that will store the size of the serialized key
 * @return 0 on success, -1 on failure.
 */
int DiffieHellman::serializeEphemeralKey(EVP_PKEY* ephemeral_key, uint8_t*& serialized_ephemeral_key,
                                         int& serialized_ephemeral_key_size) {
    // Create a new memory BIO structure
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        cerr << "DiffieHellman - Error in creating the memory BIO structure" << endl;
        BIO_free(bio);
        return -1;
    }
    // Serializes the ephemeral key (saved in an EVP_PKEY structure) into PEM format and writes it in the BIO
    if (!PEM_write_bio_PUBKEY(bio, ephemeral_key)) {
        cerr << "DiffieHellman - Error in creating the ephemeral key into the BIO structure" << endl;
        BIO_free(bio);
        return -1;
    }
    // Get the size of the serialized key from the BIO
    const void *memory_BIO_buffer;
    serialized_ephemeral_key_size = BIO_get_mem_data(bio, &memory_BIO_buffer);
    if (serialized_ephemeral_key_size < 0) {
        cerr << "DiffieHellman - Error in getting the memory data from BIO" << endl;
        BIO_free(bio);
        return -1;
    }
    // Allocate memory for the serialized key buffer
    serialized_ephemeral_key = new uint8_t[serialized_ephemeral_key_size];
    // Reads and extracts the serialized ephemeral key from the BIO
    int read = BIO_read(bio, serialized_ephemeral_key, serialized_ephemeral_key_size);
    if (read != serialized_ephemeral_key_size) {
        cerr << "DiffieHellman - Error in writing the serialized key into the buffer" << endl;
        BIO_free(bio);
        delete[] serialized_ephemeral_key;
        return -1;
    }
    // Deallocates the BIO structure
    BIO_free(bio);
    return 0;
}

/**
 * Deserialize the ephemeral key from a serialized buffer
 *
 * @param serialized_ephemeral_key       The buffer containing the serialized key data
 * @param serialized_ephemeral_key_size  The size of the serialized ephemeral key buffer
 * @return The deserialized ephemeral key (EVP_PKEY*), or nullptr on failure
 */
EVP_PKEY* DiffieHellman::deserializeEphemeralKey(uint8_t* serialized_ephemeral_key, int serialized_ephemeral_key_size) {
    // Create a new memory BIO structure
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        cerr << "DiffieHellman - Error in creating the memory BIO structure" << endl;
        return nullptr;
    }
    // Write the serialized key data into the memory BIO
    if (BIO_write(bio, serialized_ephemeral_key, serialized_ephemeral_key_size) <= 0) {
        cerr << "DiffieHellman - Error in writing the serialized key into the BIO" << endl;
        BIO_free(bio);
        return nullptr;
    }
    // Read the deserialized public key from the BIO
    EVP_PKEY* deserialized_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!deserialized_key) {
        cerr << "DiffieHellman - Error in reading the deserialized key from the BIO" << endl;
        BIO_free(bio);
        return nullptr;
    }
    // Free the memory BIO structure
    BIO_free(bio);
    return deserialized_key;
}

/**
 * Derives a shared secret from the given own ephemeral key and the peer's ephemeral key.
 *
 * @param own_ephemeral_key     The local ephemeral key for the Diffie-Hellman key exchange.
 * @param peer_ephemeral_key    The peer's ephemeral key received during the key exchange.
 * @param shared_secret         Output parameter to store the derived shared secret.
 * @param shared_secret_size    Output parameter to store the size of the derived shared secret.
 * @return                      0 on success, -1 on failure.
 */
int DiffieHellman::deriveSharedSecret(EVP_PKEY* own_ephemeral_key, EVP_PKEY* peer_ephemeral_key,
                                      unsigned char*& shared_secret, size_t& shared_secret_size) {
    // Create a context for deriving the shared secret
    EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(own_ephemeral_key, NULL);
    if (!derive_ctx) {
        cerr << "DiffieHellman - Error in creating the context for deriving the shared secret" << endl;
        return -1;
    }
    // Initialize the context for key derivation
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
        cerr << "DiffieHellman - Error in initialization of the context for deriving the shared secret" << endl;
        return -1;
    }
    // Set the peer's ephemeral key in the context
    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_ephemeral_key) <= 0) {
        cerr << "DiffieHellman - Error in setting the peer ephemeral key in the context" << endl;
        return -1;
    }
    // Determine the buffer size of the shared secret by performing a derivation, but writing the result nowhere
    EVP_PKEY_derive(derive_ctx, NULL, &shared_secret_size);
    // Allocate memory for the shared secret buffer
    shared_secret = new unsigned char[int(shared_secret_size)];
    // Perform again the derivation and store the derived shared secret in the shared_secret buffer
    if (EVP_PKEY_derive(derive_ctx, shared_secret, &shared_secret_size) <= 0) {
        cerr << "DiffieHellman - Error in deriving the shared secret" << endl;
        return -1;
    }
    // Cleanup the context
    EVP_PKEY_CTX_free(derive_ctx);
    return 0;
}

