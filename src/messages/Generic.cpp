#include "Generic.h"
#include "AesGcm.h"
#include "Config.h"
#include <cstring>
#include <netinet/in.h>
#include <iomanip>

using namespace std;

/**
 * Default constructor for Generic class
 */
Generic::Generic() = default;

/**
 * Constructor for Generic class
 */
Generic::Generic(uint32_t counter) {
    // Set AAD value in big endian format
    uint32_t counter_big_end = htonl(counter);
    memcpy(m_aad, &counter_big_end, Config::AAD_LEN);
}

/**
 * Destructor for Generic class
 */
Generic::~Generic() {
    delete[] m_ciphertext;
}

/**
 * Encrypts plaintext using AES-GCM algorithm.
 * @param session_key The session key for encryption
 * @param plaintext The plaintext to encrypt
 * @param plaintext_len The length of the plaintext
 * @return The length of the ciphertext or -1 if encryption fails
 */
int Generic::encrypt(const unsigned char *session_key, unsigned char *plaintext, int plaintext_len) {
    // Plaintext Encryption (generates ciphertext and tag)
    AesGcm aesGcm(session_key);
    m_ciphertext_len = aesGcm.encrypt(plaintext, plaintext_len, m_aad,
                                      Config::AAD_LEN, m_ciphertext, m_tag);
    // Set the IV value if encryption was successful
    if (m_ciphertext_len != -1) {
        memcpy(m_iv, aesGcm.getIV(), Config::IV_LEN);
    }
    // Safely delete IV
    aesGcm.cleanIV();
    return m_ciphertext_len;
}

/**
 * Decrypts ciphertext using AES-GCM algorithm.
 * @param session_key The session key for decryption
 * @param plaintext The buffer to store the decrypted plaintext
 * @return The length of the decrypted plaintext or -1 if decryption fails
 */
int Generic::decrypt(const unsigned char *session_key, unsigned char *&plaintext) {
    AesGcm aesGcm(session_key);
    return aesGcm.decrypt(m_ciphertext, m_ciphertext_len,
                          m_aad, Config::AAD_LEN,
                          m_iv, m_tag, plaintext);
}

/**
 * Serialize the Generic message into a byte buffer
 * @return A dynamically allocated byte buffer containing the serialized message
 */
uint8_t *Generic::serialize() {
    // Allocate memory for the byte buffer
    uint8_t *buffer = new(nothrow) uint8_t[Config::IV_LEN + Config::AAD_LEN +
                                           Config::AES_TAG_LEN + m_ciphertext_len];
    if (!buffer) {
        cerr << "Generic - Error during serialization: Failed to allocate memory" << endl;
        return nullptr;
    }
    // Serialize the IV, AAD, tag, and ciphertext
    int position = 0;
    memcpy(buffer, m_iv, Config::IV_LEN);
    position += Config::IV_LEN;

    memcpy(buffer + position, m_aad, Config::AAD_LEN);
    position += Config::AAD_LEN;

    memcpy(buffer + position, m_tag, Config::AES_TAG_LEN);
    position += Config::AES_TAG_LEN;

    memcpy(buffer + position, m_ciphertext, m_ciphertext_len);

    return buffer;
}

/**
 * Deserialize a byte buffer into a Generic message
 * @param buffer The byte buffer to deserialize
 * @param ciphertext_len Length of the ciphertext
 * @return A Generic object with the deserialized data
 */
Generic Generic::deserialize(uint8_t *buffer, size_t ciphertext_len) {
    // Create a Generic object for deserialization
    Generic genericMessage;

    // Deserialize the IV
    int position = 0;
    memcpy(genericMessage.m_iv, buffer, Config::IV_LEN);
    position += Config::IV_LEN;

    // Deserialize the AAD
    memcpy(genericMessage.m_aad, buffer + position, Config::AAD_LEN);
    position += Config::AAD_LEN;

    // Deserialize the tag
    memcpy(genericMessage.m_tag, buffer + position, Config::AES_TAG_LEN);
    position += Config::AES_TAG_LEN;

    // Deserialize the ciphertext
    genericMessage.m_ciphertext_len = static_cast<int>(ciphertext_len);
    genericMessage.m_ciphertext = new uint8_t[ciphertext_len];
    memcpy(genericMessage.m_ciphertext, buffer + position, ciphertext_len);

    return genericMessage;
}

/**
 * Get the size of the Generic message in bytes
 * @param plaintext_len The length of the plaintext
 * @return The size of the Generic message
 */
size_t Generic::getMessageSize(size_t plaintext_len) {
    return Config::IV_LEN +
           Config::AAD_LEN +
           Config::AES_TAG_LEN +
           plaintext_len; // Is equal to the ciphertext length
}

/**
 * Print method to display the Generic message's fields
 */
void Generic::print(size_t plaintext_len) const {
    cout << "MESSAGE:" << endl;

    cout << "IV: ";
    for (unsigned char i : m_iv) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(i);
    }
    cout << endl;

    cout << "AAD: ";
    for (unsigned char i : m_aad) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(i);
    }
    cout << endl;

    cout << "TAG: ";
    for (unsigned char i : m_tag) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(i);
    }
    cout << endl;

    cout << "Ciphertext: ";
    for (int i = 0; i < plaintext_len; i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(m_ciphertext[i]);
    }
    cout << dec << endl;

    cout << "Ciphertext len: " << m_ciphertext_len << endl << endl;
}







