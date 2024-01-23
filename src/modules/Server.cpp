#include <iostream>
#include <openssl/pem.h>

#include "Generic.h"
#include "Server.h"
#include "CodesManager.h"
#include "Authentication.h"
#include "SimpleMessage.h"
#include "DiffieHellman.h"
#include "Hash.h"
#include "CertificateManager.h"
#include "AesGcm.h"
#include "DigitalSignatureManager.h"

using namespace std;

Server::Server(SocketManager *socket) {
    m_socket = socket;
}

Server::~Server() {
    delete m_socket;
    OPENSSL_cleanse(m_session_key, Config::AES_KEY_LEN);
    delete[] m_socket;
}

void Server::incrementCounter() {
    // Check if re-authenticationRequest is needed
    if (m_counter == Config::MAX_COUNTER_VALUE) {
        if (authenticationRequest() != static_cast<int>(Return::AUTHENTICATION_SUCCESS)) {
            throw static_cast<int>(Return::AUTHENTICATION_FAILURE);
        }
    } else {
        m_counter++;
    }
}

int Server::authenticationRequest() {
    // Authentication M1 message
    size_t authentication_m1_length = AuthenticationM1::getMessageSize();
    uint8_t* serialized_message = new uint8_t[authentication_m1_length];
    int result = m_socket->receive(serialized_message, authentication_m1_length);
    if (result != 0) {
        delete[] serialized_message;
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }

    cout << "Authentication M1 ephemeral key and client's username received!" << endl;

    AuthenticationM1 authenticationM1 = AuthenticationM1::deserialize(serialized_message);
    OPENSSL_cleanse(serialized_message, authentication_m1_length);

    // Authentication M2 message
    string username_file = "../resources/public_keys/" + (string)authenticationM1.getMUsername() + "_key.pem";
    BIO *bio = BIO_new_file(username_file.c_str(), "r");
    EVP_PKEY* client_public_key = nullptr;
    SimpleMessage simpleMessage;
    size_t serialized_message_length;
    if (!bio) {
        BIO_free(bio);
        cerr << "Authentication M1 - Error in creating the bio structure for the Client public key!" << endl;
        return static_cast<int>(Return::AUTHENTICATION_FAILURE);
    }
    m_username = (string)authenticationM1.getMUsername();
    client_public_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!client_public_key) {
        simpleMessage.setMMessageCode(static_cast<int>(Result::NACK));
        cerr << "AuthenticationM2 - Username " << m_username << " not found!" << endl;
    } else {
        simpleMessage.setMMessageCode(static_cast<int>(Result::ACK));
        cout << "AuthenticationM2 - Username " << m_username << " found!" << endl;
    }
    BIO_free(bio);

    serialized_message = simpleMessage.serialize();
    serialized_message_length = SimpleMessage::getMessageSize();
    result = m_socket->send(serialized_message, serialized_message_length);
    OPENSSL_cleanse(serialized_message, serialized_message_length);
    if (result == -1) {
        EVP_PKEY_free(client_public_key);
        return static_cast<int>(Return::SEND_FAILURE);
    }
    if (simpleMessage.getMMessageCode() != static_cast<int>(Result::ACK)) {
        EVP_PKEY_free(client_public_key);
        return static_cast<int>(Error::USERNAME_NOT_FOUND);
    }
    cout << "Authentication M2 - Username ACK/NACK sent to the client!" << endl;

    // Authentication M3
    string private_key_file = "../resources/private_keys/Server_key.pem";
    bio = BIO_new_file(private_key_file.c_str(), "r");
    if (!bio) {
        BIO_free(bio);
        cerr << "Authentication M3 - Error in creating the bio structure for the Server private key!" << endl;
        return static_cast<int>(Return::AUTHENTICATION_FAILURE);
    }
    EVP_PKEY* server_private_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if(!server_private_key) {
        EVP_PKEY_free(client_public_key);
        cerr << "Server private key not found!" << endl;
        return static_cast<int>(Return::AUTHENTICATION_FAILURE);
    }

    DiffieHellman dh_instance;
    EVP_PKEY* server_ephemeral_key = dh_instance.generateEphemeralKey();

    EVP_PKEY* client_ephemeral_key = dh_instance.deserializeEphemeralKey(
            const_cast<uint8_t *>(authenticationM1.getMEphemeralKey()),
            authenticationM1.getMEphemeralKeyLen());
    uint8_t* shared_secret = nullptr;
    size_t shared_secret_length;
    result = dh_instance.deriveSharedSecret(server_ephemeral_key, client_ephemeral_key,
                                            shared_secret, shared_secret_length);
    EVP_PKEY_free(client_ephemeral_key);
    if (result != 0) {
        OPENSSL_cleanse(shared_secret, shared_secret_length);
        delete[] shared_secret;
        EVP_PKEY_free(server_ephemeral_key);
        EVP_PKEY_free(server_private_key);
        EVP_PKEY_free(client_public_key);
        return static_cast<int>(Return::AUTHENTICATION_FAILURE);
    }

    unsigned char* session_key = nullptr;
    unsigned int session_key_length;
    Hash::generateSHA256(shared_secret, shared_secret_length, session_key,
                         session_key_length);
    memcpy(m_session_key, session_key, Config::AES_KEY_LEN * sizeof(unsigned char));
    OPENSSL_cleanse(shared_secret, shared_secret_length);
    delete[] shared_secret;
    OPENSSL_cleanse(session_key, session_key_length);
    delete[] session_key;

    cout << "AuthenticationM3 - Session Key generated!" << endl;

    const char *certificate_file = "../resources/certificates/Server_cert.pem";
    CertificateManager* certificateManager = CertificateManager::getInstance();
    X509* certificate = certificateManager->loadCertificate(certificate_file);

    uint8_t* serialized_certificate = nullptr;
    int serialized_certificate_length = 0;
    certificateManager->serializeCertificate(certificate, serialized_certificate, serialized_certificate_length);
    X509_free(certificate);

    uint8_t* serialized_ephemeral_key = nullptr;
    int serialized_ephemeral_key_length = 0;
    result = dh_instance.serializeEphemeralKey(server_ephemeral_key, serialized_ephemeral_key,
                                               serialized_ephemeral_key_length);
    EVP_PKEY_free(server_ephemeral_key);
    if (result != 0) {
        EVP_PKEY_free(server_private_key);
        OPENSSL_cleanse(serialized_certificate, serialized_certificate_length);
        delete[] serialized_certificate;
        OPENSSL_cleanse(serialized_ephemeral_key, serialized_ephemeral_key_length);
        delete[] serialized_ephemeral_key;
        return static_cast<int>(Return::AUTHENTICATION_FAILURE);
    }

    int ephemeral_key_buffer_length = authenticationM1.getMEphemeralKeyLen() + serialized_ephemeral_key_length;
    uint8_t* ephemeral_key_buffer = new uint8_t [ephemeral_key_buffer_length];
    memcpy(ephemeral_key_buffer, authenticationM1.getMEphemeralKey(),
           authenticationM1.getMEphemeralKeyLen());
    memcpy(ephemeral_key_buffer + authenticationM1.getMEphemeralKeyLen(), serialized_ephemeral_key,
           serialized_ephemeral_key_length);

    unsigned char* digital_signature = nullptr;
    unsigned int digital_signature_length;
    DigitalSignatureManager digitalSignatureManager;
    digitalSignatureManager.generateDS(ephemeral_key_buffer, ephemeral_key_buffer_length,
                                       digital_signature, digital_signature_length, server_private_key);
    EVP_PKEY_free(server_private_key);

    unsigned char *ciphertext = nullptr;
    m_counter = 0;
    unsigned char aad[sizeof(uint32_t)];
    memcpy(aad, &m_counter, Config::AAD_LEN);
    unsigned char tag[Config::AES_TAG_LEN];
    AesGcm aesGcm = AesGcm(m_session_key);
    int ciphertext_length = aesGcm.encrypt(digital_signature, static_cast<int>(digital_signature_length),
                                           aad, Config::AAD_LEN,
                                           ciphertext, tag);
    delete[] digital_signature;

    if (ciphertext_length == -1) {
        delete[] serialized_message;
        delete[] serialized_certificate;
        delete[] serialized_ephemeral_key;
        delete[] ciphertext;
        delete[] ephemeral_key_buffer;
        cerr << "AuthenticationM3 - Error during the encryption!" << endl;
        return static_cast<int>(Return::ENCRYPTION_FAILURE);
    }

    AuthenticationM3 authenticationM3(serialized_ephemeral_key,
                                      serialized_ephemeral_key_length, aesGcm.getIV(),
                                      aad, tag, digital_signature,
                                      serialized_certificate, serialized_certificate_length);
    serialized_message = authenticationM3.serialize();
    result = m_socket->send(serialized_message, authenticationM3.getMessageSize());
    OPENSSL_cleanse(serialized_message, serialized_message_length);
    delete[] serialized_certificate;
    delete[] serialized_ephemeral_key;
    delete[] ciphertext;
    if (result != 0) {
        EVP_PKEY_free(client_public_key);
        delete[] ephemeral_key_buffer;
        cerr << "AuthenticationM3 - Error in sending the M3 to the client!" << endl;
        return static_cast<int>(Return::SEND_FAILURE);
    }
    cout << "AuthenticationM3 message sent to the client!" << endl;






    return static_cast<int>(Return::AUTHENTICATION_SUCCESS);
}

int Server::listRequest(uint8_t *plaintext) {
    return 0;
}

int Server::downloadRequest(uint8_t *plaintext) {
    return 0;
}

int Server::uploadRequest(uint8_t *plaintext) {
    return 0;
}

int Server::renameRequest(uint8_t *plaintext) {
    return 0;
}

int Server::deleteRequest(uint8_t *plaintext) {
    return 0;
}

int Server::logout(uint8_t *plaintext) {
    return 0;
}

void Server::run() {
    try {
        // Perform login
        int result = authenticationRequest();
        if (result != static_cast<int>(Return::AUTHENTICATION_SUCCESS)) {
            cout << "Server - Error! Login failed with error code: " << result << endl;
            return;
        }
//        // Determine the expected size of the message buffer
//        size_t message_size = Generic::getMessageSize(Config::MAX_PACKET_SIZE);
//        while (true) {
//            // Allocate memory for the buffer to receive the first message
//            auto *serialized_message = new uint8_t[message_size];
//            if (m_socket->receive(serialized_message, message_size) == -1) {
//                cout << "Server - Error! Receive failed" << endl;
//                return;
//            }
//            // Deserialize the received message
//            Generic generic_message = Generic::deserialize(serialized_message, message_size);
//            delete[] serialized_message;
//            // Allocate memory for the plaintext
//            auto *plaintext = new uint8_t[message_size];
//            // Decrypt the received ciphertext
//            if (generic_message.decrypt(m_session_key, plaintext) == -1) {
//                cout << "Server - Error! Decryption failed" << endl;
//                return;
//            }
//            // Taking the command code as the first byte of plaintext
//            uint8_t command = plaintext[0];
//
//            switch (command) {
//                case static_cast<uint8_t>(Message::LIST_REQUEST):
//                    listRequest(plaintext);
//                    break;
//
//                case static_cast<uint8_t>(Message::DOWNLOAD_REQUEST):
//                    downloadRequest(plaintext);
//                    break;
//
//                case static_cast<uint8_t>(Message::UPLOAD_REQUEST):
//                    uploadRequest(plaintext);
//                    break;
//
//                case static_cast<uint8_t>(Message::RENAME_REQUEST):
//                    renameRequest(plaintext);
//                    break;
//
//                case static_cast<uint8_t>(Message::DELETE_REQUEST):
//                    deleteRequest(plaintext);
//                    break;
//
//                case static_cast<uint8_t>(Message::LOGOUT_REQUEST):
//                    logout(plaintext);
//                    return;
//
//                default:
//                    cerr << "Server - Invalid command received." << endl;
//                    break;
//            }
//        }
    } catch (const exception &e) {
        cerr << "Server - Exception in run: " << e.what() << endl;
    } catch (int error_code) {
        // To add checks on different errors thrown by the functions
    }

}
