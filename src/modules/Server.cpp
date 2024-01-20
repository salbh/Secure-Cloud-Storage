#include <iostream>
#include <openssl/pem.h>

#include "Generic.h"
#include "Server.h"
#include "CodesManager.h"
#include "Authentication.h"
#include "SimpleMessage.h"

using namespace std;

Server::Server(SocketManager *socket) {
    m_socket = socket;
}

Server::~Server() {
    delete m_socket;
    OPENSSL_cleanse(m_session_key, Config::AES_KEY_LEN);
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
        OPENSSL_cleanse(serialized_message, authentication_m1_length);
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }

    cout << "Authentication M1 ephemeral key and client's username received!" << endl;

    AuthenticationM1 authenticationM1 = AuthenticationM1::deserialize(serialized_message);
    OPENSSL_cleanse(serialized_message, authentication_m1_length);

    // Authentication M2 message
    string username = "../resources/public_keys/" + (string)authenticationM1.getMUsername() + "_key.pem";
    BIO *bio = BIO_new_file(username.c_str(), "r");
    EVP_PKEY* client_public_key = nullptr;
    SimpleMessage simpleMessage;
    size_t serialized_message_length;
    if (!bio) {
        simpleMessage.setMMessageCode(static_cast<int>(Error::USERNAME_NOT_FOUND));
        cout << "AuthenticationM2 - Username " << username << " not found!" << endl;
    } else {
        m_username = (string)authenticationM1.getMUsername();
        client_public_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
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
    cout << "Authentication M2 - Username ACK sent to the client!" << endl;
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
