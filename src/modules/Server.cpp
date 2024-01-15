#include <iostream>
#include "Generic.h"
#include "Server.h"

#include "CodesManager.h"

using namespace std;

Server::Server(SocketManager *socket) {
    m_socket = socket;
}

Server::~Server() {
    delete m_socket;
    OPENSSL_cleanse(m_session_key, Config::AES_KEY_LEN);
}

void Server::incrementCounter() {

}

int Server::login() {
    return 0;
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
        if (login() != 0) {
            cout << "Server - Error! Login failed" << endl;
            return;
        }
        // Determine the expected size of the message buffer
        size_t message_size = Generic::getSize(Config::MAX_PACKET_SIZE);
        while (true) {
            // Allocate memory for the buffer to receive the first message
            auto *serialized_message = new uint8_t[message_size];
            if (m_socket->receive(serialized_message, message_size) == -1) {
                cout << "Server - Error! Receive failed" << endl;
                return;
            }
            // Deserialize the received message
            Generic generic_message = Generic::deserialize(serialized_message, message_size);
            delete[] serialized_message;
            // Allocate memory for the plaintext
            auto *plaintext = new uint8_t[message_size];
            // Decrypt the received ciphertext
            if (generic_message.decrypt(m_session_key, plaintext) == -1) {
                cout << "Server - Error! Decryption failed" << endl;
                return;
            }
            // Taking the command code as the first byte of plaintext
            uint8_t command = plaintext[0];

            switch (command) {
                case static_cast<uint8_t>(Message::LIST_REQUEST):
                    listRequest(plaintext);
                    break;

                case static_cast<uint8_t>(Message::DOWNLOAD_REQUEST):
                    downloadRequest(plaintext);
                    break;

                case static_cast<uint8_t>(Message::UPLOAD_REQUEST):
                    uploadRequest(plaintext);
                    break;

                case static_cast<uint8_t>(Message::RENAME_REQUEST):
                    renameRequest(plaintext);
                    break;

                case static_cast<uint8_t>(Message::DELETE_REQUEST):
                    deleteRequest(plaintext);
                    break;

                case static_cast<uint8_t>(Message::LOGOUT_REQUEST):
                    logout(plaintext);
                    return;

                default:
                    cerr << "Server - Invalid command received." << endl;
                    break;
            }
        }
    } catch (const exception &e) {
        cerr << "Server - Exception in run: " << e.what() << endl;
    } catch (int error_code) {
        // To add checks on different errors thrown by the functions
    }
}
