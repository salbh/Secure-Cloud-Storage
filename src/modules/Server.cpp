#include <iostream>

#include "Generic.h"
#include "Server.h"
#include "CodesManager.h"
#include "SimpleMessage.h"
#include "FileManager.h"
#include "List.h"

using namespace std;

int counter_instance = 1;

Server::Server(SocketManager *socket) {
    m_socket = socket;
}

Server::~Server() {
    delete m_socket;
    OPENSSL_cleanse(m_session_key, Config::AES_KEY_LEN);
}

void Server::incrementCounter() {
    // Check if re-authentication is needed
    if (m_counter == Config::MAX_COUNTER_VALUE) {
        if (authentication() != static_cast<int>(Return::LOGIN_SUCCESS)) {
            throw static_cast<int>(Return::LOGIN_FAILURE);
        }
    } else {
        m_counter++;
    }
}

int Server::authentication() {
    return 0;
}

int Server::listRequest(uint8_t *plaintext) {
    // Safely clean plaintext buffer
    OPENSSL_cleanse(plaintext, SimpleMessage::getMessageSize());
    delete[] plaintext;

    incrementCounter();

    // Send message ListM2

    // Get the list of files in the user's folder
    string files = FileManager::getFilesList("data/" + m_username);
    if (files == "error") {
        return static_cast<int>(Return::WRONG_PATH);
    }
    // If the path is correct send the message

    // Define the list size
    uint32_t list_size = files.length();
    // Include the null terminator char if the string is not empty
    if (list_size != 0) {
        list_size++;
    }
    // Create the ListM2 message
    size_t list_msg2_len = ListM2::getMessageSize();
    ListM2 list_msg2(list_size);
    // Serialize the ListM2 message to obtain a byte buffer
    uint8_t *serialized_message = list_msg2.serialize();
    // Create a Generic message with the current counter value
    Generic generic_msg2(m_counter);
    // Encrypt the serialized plaintext and init the GenericMessage fields
    if (generic_msg2.encrypt(m_session_key, serialized_message,
                             static_cast<int>(list_msg2_len)) == -1) {
        cout << "Client - Error during encryption" << endl;
        return static_cast<int>(Return::ENCRYPTION_FAILURE);
    }
    // Serialize Generic message
    serialized_message = generic_msg2.serialize();
    if (m_socket->send(serialized_message,
                       Generic::getMessageSize(list_msg2_len)) == -1) {
        delete[] serialized_message;
        return static_cast<int>(Return::SEND_FAILURE);
    }
    delete[] serialized_message;

    incrementCounter();

    // If list size is 0 no other messages will be sent
    if (list_size == 0) {
        cout << "FileManager - The user has no files in the folder." << endl;
        return static_cast<int>(Return::SUCCESS);
    }

    // Send message ListM3

    // Get the file list in a byte buffer
    auto *file_list = new uint8_t[list_size];
    memcpy(file_list, files.c_str(), list_size);
    // Create the ListM3 message
    size_t list_msg3_len = ListM3::getMessageSize(list_size);
    ListM3 list_msg3(list_size, file_list);
    // Serialize the ListM3 message to obtain a byte buffer
    serialized_message = list_msg3.serialize(list_size);
    // Create a Generic message with the current counter value
    Generic generic_msg3(m_counter);
    // Encrypt the serialized plaintext and init the GenericMessage fields
    if (generic_msg3.encrypt(m_session_key, serialized_message,
                             static_cast<int>(list_msg3_len)) == -1) {
        cout << "Client - Error during encryption" << endl;
        return static_cast<int>(Return::ENCRYPTION_FAILURE);
    }
    // Serialize Generic message
    serialized_message = generic_msg3.serialize();
    if (m_socket->send(serialized_message,
                       Generic::getMessageSize(list_msg3_len)) == -1) {
        delete[] serialized_message;
        return static_cast<int>(Return::SEND_FAILURE);
    }
    delete[] serialized_message;

    incrementCounter();

    return static_cast<int>(Return::SUCCESS);
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
        if (authentication() != 0) {
            cout << "Server - Error! Login failed" << endl;
            return;
        }
        // Determine the expected size of the message buffer
        size_t message_size = Generic::getMessageSize(Config::MAX_PACKET_SIZE);
        while (true) {
            // Allocate memory for the buffer to receive the first message
            auto *serialized_message = new uint8_t[message_size];
            if (m_socket->receive(serialized_message, message_size) == -1) {
                cout << "Server - Error! Receive failed" << endl;
                return;
            }
            // Deserialize the received message
            Generic generic_message = Generic::deserialize(serialized_message,
                                                           Config::MAX_PACKET_SIZE);
            delete[] serialized_message;
            // Allocate memory for the plaintext
            auto *plaintext = new uint8_t[Config::MAX_PACKET_SIZE];
            // Decrypt the received ciphertext
            if (generic_message.decrypt(m_session_key, plaintext) == -1) {
                cout << "Server - Error! Decryption failed" << endl;
                return;
            }
            // Check the counter value to prevent replay attacks
            if (m_counter != generic_message.getCounter()) {
                throw static_cast<int>(Return::WRONG_COUNTER);
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
    cout << "Server running instance: " << counter_instance << endl;
    counter_instance++;
}
