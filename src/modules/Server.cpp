#include <iostream>

#include "Generic.h"
#include "Server.h"
#include "CodesManager.h"
#include "Upload.h"
#include "FileManager.h"
#include "SimpleMessage.h"

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
        m_counter = 0;
    } else {
        m_counter++;
    }
}

int Server::authentication() {
    return 0;
}

int Server::listRequest(uint8_t *plaintext) {
    return 0;
}

int Server::downloadRequest(uint8_t *plaintext) {
    return 0;
}


/**
 * Server side upload request operation
 * 1) Waits an upload message request from the client specifying file name and file size (UploadM1 message type)
 * 2) Send a response to the client indicating the success or failure of the upload request (SimpleMessage)
 * 3) Wait for the chunks inside M3+i messages and write into the file (UploadMi Message)
 * 4) Send the final response to the client after writing all file chunks in the file, indicating the overall success
 * or failure of the file upload (SimpleMessage)
 *
 * @param plaintext The message containing the file name and file size
 * @return An integer value representing the success or failure of the upload process.
 */
int Server::uploadRequest(uint8_t *plaintext) {

    // 1) Receive the upload request message M1 (UploadM1 message)
    UploadM1 upload_msg1 = UploadM1::deserializeUploadM1(plaintext);
    // Safely clean plaintext buffer
    OPENSSL_cleanse(plaintext, UploadM1::getSizeUploadM1());
    delete[] plaintext;

    // Increment counter against replay attack
    incrementCounter();


    // 2) Send the success message (if file does not exist) or fail message (if file exist) M2 (SimpleMessage)
    SimpleMessage upload_msg2;
    // Check if the file already exists, otherwise create the message to send
    string file_path = "../data/" + m_username + "/" + (string)upload_msg1.getFilename();
    if (FileManager::isFilePresent(file_path)) {
        cout << "Server - uploadRequest() - Error during upload request! File already exists" << endl;
        return static_cast<int>(Error::FILENAME_ALREADY_EXISTS);
    }
    else {
        // Create success message to send to the Client
        upload_msg2 = SimpleMessage(static_cast<uint8_t>(Result::ACK));
    }

    // Serialize the message to send to the Client
    uint8_t* serialized_message = upload_msg2.serialize();
    // Determine the size of the message to send
    size_t upload_msg2_len = SimpleMessage::getMessageSize();

    // Create a Generic message with the current counter value
    Generic generic_msg2(m_counter);
    // Encrypt the serialized plaintext and init the Generic message fields
    if (generic_msg2.encrypt(m_session_key, serialized_message,static_cast<int>(upload_msg2_len)) == -1) {
        cout << "Server - uploadRequest() - Error during encryption" << endl;
        return static_cast<int>(Return::ENCRYPTION_FAILURE);
    }
    // Safely clean plaintext buffer
    OPENSSL_cleanse(serialized_message, Config::MAX_PACKET_SIZE);
    // Serialize and Send Generic message (SimpleMessage)
    serialized_message = generic_msg2.serialize();
    if (m_socket->send(serialized_message,Generic::getMessageSize(upload_msg2_len)) == -1) {
        return static_cast<int>(Return::SEND_FAILURE);
    }

    //Free the memory allocated for UploadM1 message
    delete[] serialized_message;

    // Increment counter against replay attack
    incrementCounter();


    //3) Receive the file chunks messages M3+i from the Client (UploadMi)
    // Prepare the file reception
    FileManager file_to_upload(file_path, FileManager::OpenMode::WRITE);
    size_t file_size = upload_msg1.getFileSize() != 0 ? upload_msg1.getFileSize() : 4UL * 1024 * 1024 * 1024;
    file_to_upload.initFileInfo(file_size);

    // Compute the chunk size and upload state variable to check the received size
    size_t chunk_size = file_to_upload.getFileSize() / file_to_upload.getChunksNum();
    size_t received_size = 0;


    // Receive all file chunks and write to the file
    for (size_t i = 0; i < file_to_upload.getChunksNum(); ++i) {
        //Receive the M3+i message
        // Get the chunk size
        if (i == file_to_upload.getChunksNum() - 1)
            chunk_size = file_to_upload.getLastChunkSize();


        // Determine the size of the message to receive
        size_t upload_msg3i_len = UploadMi::getSizeUploadMi(chunk_size);

        // Allocate memory for the buffer to receive the Generic message
        serialized_message = new uint8_t[Generic::getMessageSize(upload_msg3i_len)];
        if (m_socket->receive(serialized_message, upload_msg3i_len) == -1) {
            delete[] serialized_message;
            return static_cast<int>(Return::RECEIVE_FAILURE);
        }

        // Deserialize the received Generic message
        Generic generic_msg3i = Generic::deserialize(serialized_message, upload_msg3i_len);
        delete[] serialized_message;
        // Allocate memory for the plaintext buffer
        auto *plaintext = new uint8_t[upload_msg3i_len];
        // Decrypt the Generic message to obtain the serialized message
        if (generic_msg3i.decrypt(m_session_key, plaintext) == -1) {
            return static_cast<int>(Return::DECRYPTION_FAILURE);
        }
        // Check the counter value to prevent replay attacks
        if (m_counter != generic_msg3i.getCounter()) {
            return static_cast<int>(Return::WRONG_COUNTER);
        }
        // Deserialize the upload message 3+i received (UploadMi)
        UploadMi upload_msg3i = UploadMi::deserializeUploadMi(plaintext, chunk_size);
        // Safely clean plaintext buffer
        OPENSSL_cleanse(plaintext, upload_msg2_len);
        delete[] plaintext;

        // Increment counter against replay attack
        incrementCounter();

        // Write the received chunk in the file
        file_to_upload.writeChunk(upload_msg3i.getChunk(), chunk_size);

        // Log upload status
        received_size += chunk_size;
        cout << "Server - uploadRequest() - Received " << received_size << "bytes/" << file_to_upload.getFileSize() << "bytes";
    }


    // 4) Send the final packet M3+i+1 message (success file upload. Simple Message)
    SimpleMessage upload_msg3i1 = SimpleMessage(static_cast<uint8_t>(Result::ACK));

    // Serialize the message to send to the Client
    serialized_message = upload_msg3i1.serialize();
    // Determine the size of the message to send
    size_t upload_msg3i1_len = SimpleMessage::getMessageSize();

    // Create a Generic message with the current counter value
    Generic generic_msg3i1(m_counter);
    // Encrypt the serialized plaintext and init the Generic message fields
    if (generic_msg3i1.encrypt(m_session_key, serialized_message,static_cast<int>(upload_msg3i1_len)) == -1) {
        cout << "Server - uploadRequest() - Error during encryption" << endl;
        return static_cast<int>(Return::ENCRYPTION_FAILURE);
    }
    // Safely clean plaintext buffer
    OPENSSL_cleanse(serialized_message, Config::MAX_PACKET_SIZE);
    // Serialize and Send Generic message (SimpleMessage)
    serialized_message = generic_msg3i1.serialize();
    if (m_socket->send(serialized_message,Generic::getMessageSize(upload_msg3i1_len)) == -1) {
        return static_cast<int>(Return::SEND_FAILURE);
    }

    //Free the memory allocated for UploadM1 message
    delete[] serialized_message;

    // Increment counter against replay attack
    incrementCounter();


    // Successful upload
    return static_cast<int>(Return::SUCCESS);
}

int Server::renameRequest(uint8_t *plaintext) {
    return 0;
}

int Server::deleteRequest(uint8_t *plaintext) {
    return 0;
}

int Server::logoutRequest(uint8_t *plaintext) {
    // 1) Receive the logout request message M1 (SimpleMessage message)
    SimpleMessage logout_msg1 = SimpleMessage::deserialize(plaintext);
    // Safely clean plaintext buffer
    OPENSSL_cleanse(plaintext, SimpleMessage::getMessageSize());
    delete[] plaintext;

    // Increment counter against replay attack
    incrementCounter();


    // 2) Send the success message (if file does not exist) or fail message (if file exist) M2 (SimpleMessage)
    SimpleMessage logout_msg2 = SimpleMessage(static_cast<uint8_t>(Result::ACK));;
    // Check if the file already exists, otherwise create the message to send

    // Serialize the message to send to the Client
    uint8_t* serialized_message = logout_msg2.serialize();
    // Determine the size of the message to send
    size_t logout_msg2_len = SimpleMessage::getMessageSize();

    // Create a Generic message with the current counter value
    Generic generic_msg2(m_counter);
    // Encrypt the serialized plaintext and init the Generic message fields
    if (generic_msg2.encrypt(m_session_key, serialized_message,static_cast<int>(logout_msg2_len)) == -1) {
        cout << "Server - logoutRequest() - Error during encryption" << endl;
        return static_cast<int>(Return::ENCRYPTION_FAILURE);
    }

    //Delete The Session Key (Logout operation)
    OPENSSL_cleanse(m_session_key, sizeof(m_session_key));

    // Safely clean plaintext buffer
    OPENSSL_cleanse(serialized_message, Config::MAX_PACKET_SIZE);
    // Serialize and Send Generic message (SimpleMessage)
    serialized_message = generic_msg2.serialize();
    if (m_socket->send(serialized_message,Generic::getMessageSize(logout_msg2_len)) == -1) {
        return static_cast<int>(Return::SEND_FAILURE);
    }

    //Free the memory allocated for UploadM1 message
    delete[] serialized_message;


    // Successful logout
    return static_cast<int>(Return::SUCCESS);
}

void Server::run() {
//    try {
//        // Perform login
//        if (login() != 0) {
//            cout << "Server - Error! Login failed" << endl;
//            return;
//        }
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
//    } catch (const exception &e) {
//        cerr << "Server - Exception in run: " << e.what() << endl;
//    } catch (int error_code) {
//        // To add checks on different errors thrown by the functions
//    }
    cout << "Server running instance: " << counter_instance << endl;
    counter_instance++;
}

