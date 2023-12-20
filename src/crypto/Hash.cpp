#include "Hash.h"
#include <openssl/evp.h>

void Hash::generateSHA256(unsigned char* input,
                          size_t input_size,
                          unsigned char*& digest,
                          unsigned int& digest_size) {

    // Allocate memory for the digest based on the size of SHA-256 hash
    digest = new unsigned char[EVP_MD_size(EVP_sha256())];

    // Create a new context for the SHA-256 hash operation
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // Initialize the context with the SHA-256 hashing algorithm
    EVP_DigestInit(ctx, EVP_sha256());

    // Update the context with the input data
    EVP_DigestUpdate(ctx, input, input_size);

    // Finalize the hash computation and obtain the resulting digest
    EVP_DigestFinal(ctx, digest, &digest_size);

    // Free the memory associated with the context
    EVP_MD_CTX_free(ctx);
}
