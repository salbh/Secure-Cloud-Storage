#include <iostream>
#include <thread>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
#include <sstream>

#include "SocketManager.h"
#include "Client.h"
#include "FileManager.h"
#include "CodesManager.h"
#include "SimpleMessage.h"
#include "Generic.h"
#include "List.h"
#include "Download.h"

Client::Client() = default;

Client::~Client() {

}

int Client::authentication() {
    return 0;
}

int Client::listRequest() {
    // Send message ListM1

    // Determine the size of the plaintext and ciphertext
    size_t simple_msg_len = SimpleMessage::getMessageSize();
    // Create a SimpleMessage with LIST_REQUEST code
    SimpleMessage simple_message(static_cast<uint8_t>(Message::LIST_REQUEST));
    // Serialize the SimpleMessage to obtain a byte buffer
    uint8_t *serialized_message = simple_message.serialize();
    // Create a Generic message with the current counter value
    Generic generic_msg1(m_counter);
    // Encrypt the serialized plaintext and init the GenericMessage fields
    if (generic_msg1.encrypt(m_session_key, serialized_message,
                             static_cast<int>(simple_msg_len)) == -1) {
        cout << "Client - Error during encryption" << endl;
        return static_cast<int>(Return::ENCRYPTION_FAILURE);
    }
    // Serialize Generic message
    serialized_message = generic_msg1.serialize();
    if (m_socket->send(serialized_message,
                       Generic::getMessageSize(simple_msg_len)) == -1) {
        delete[] serialized_message;
        return static_cast<int>(Return::SEND_FAILURE);
    }
    delete[] serialized_message;

    incrementCounter();

    // Receive message ListM2

    // Determine the size of the message
    size_t list_msg2_len = ListM2::getMessageSize();
    size_t generic_msg2_len = Generic::getMessageSize(list_msg2_len);
    // Allocate memory for the buffer to receive the Generic message
    serialized_message = new uint8_t[generic_msg2_len];
    // Receive the Generic message from the server
    if (m_socket->receive(serialized_message, generic_msg2_len) == -1) {
        delete[] serialized_message;
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }
    // Deserialize the received Generic message
    Generic generic_msg2 = Generic::deserialize(serialized_message, list_msg2_len);
    delete[] serialized_message;
    // Allocate memory for the plaintext buffer
    auto *plaintext = new uint8_t[list_msg2_len];
    // Decrypt the Generic message to obtain the serialized message
    if (generic_msg2.decrypt(m_session_key, plaintext) == -1) {
        return static_cast<int>(Return::DECRYPTION_FAILURE);
    }
    ListM2 list_msg2 = ListM2::deserialize(plaintext);
    // Safely clean plaintext buffer
    OPENSSL_cleanse(plaintext, list_msg2_len);
    delete[] plaintext;
    // Check the counter value to prevent replay attacks
    if (m_counter != generic_msg2.getCounter()) {
        return static_cast<int>(Return::WRONG_COUNTER);
    }

    incrementCounter();

    // Check the received message code
    if (list_msg2.getMessageCode() != static_cast<uint8_t>(Message::LIST_ACK)) {
        return static_cast<int>(Return::WRONG_MSG_CODE);
    }

    // Receive message ListM3

    // Get list size from the second message
    uint32_t list_size = list_msg2.getListSize();
    // If list size is 0 no other messages will be received
    if (list_size == 0) {
        cout << "There are no files in your storage." << endl;
        return static_cast<int>(Return::SUCCESS);
    }
    // Get the size of the third message and init buffer
    size_t list_msg3_len = ListM3::getMessageSize(list_size);
    size_t generic_msg3_len = Generic::getMessageSize(list_msg3_len);
    serialized_message = new uint8_t[generic_msg3_len];
    // Receive the Generic message from the server
    if (m_socket->receive(serialized_message, generic_msg3_len) == -1) {
        delete[] serialized_message;
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }
    // Deserialize the received Generic message
    Generic generic_msg3 = Generic::deserialize(serialized_message, list_msg3_len);
    delete[] serialized_message;
    // Allocate memory for the plaintext buffer
    plaintext = new uint8_t[list_msg3_len];
    // Decrypt the Generic message to obtain the serialized message
    if (generic_msg3.decrypt(m_session_key, plaintext) == -1) {
        return static_cast<int>(Return::DECRYPTION_FAILURE);
    }
    ListM3 list_msg3 = ListM3::deserialize(plaintext, list_size);
    // Safely clean plaintext buffer
    OPENSSL_cleanse(plaintext, list_msg3_len);
    delete[] plaintext;
    // Check the counter value to prevent replay attacks
    if (m_counter != generic_msg3.getCounter()) {
        return static_cast<int>(Return::WRONG_COUNTER);
    }

    incrementCounter();

    // Check the received message code
    if (list_msg3.getMessageCode() != static_cast<uint8_t>(Message::LIST_RESPONSE)) {
        return static_cast<int>(Return::WRONG_MSG_CODE);
    }

    // Show the obtained list to the user
    cout << "----------- LIST -------------" << endl;
    istringstream file_list_stream(reinterpret_cast<char *>(list_msg3.getFileList()));
    string file_name;
    while (getline(file_list_stream, file_name, ',')) {
        cout << file_name << endl;
    }
    cout << "------------------------------" << endl;

    // Return success code if the end of the function is reached
    return static_cast<int>(Return::SUCCESS);
}

int Client::downloadRequest(const string& filename) {
    // Send message DownloadM1

    // Check if the file to download is already present
    if (FileManager::isFilePresent(filename)) {
        return static_cast<int>(Return::FILE_ALREADY_EXISTS);
    }
    size_t download_msg1_len = DownloadM1::getMessageSize();
    DownloadM1 download_msg1(filename);
    // Serialize the ListM2 message to obtain a byte buffer
    uint8_t *serialized_message = download_msg1.serialize();
    // Create a Generic message with the current counter value
    Generic generic_msg1(m_counter);
    // Encrypt the serialized plaintext and init the GenericMessage fields
    if (generic_msg1.encrypt(m_session_key, serialized_message,
                             static_cast<int>(download_msg1_len)) == -1) {
        cout << "Client - Error during encryption" << endl;
        return static_cast<int>(Return::ENCRYPTION_FAILURE);
    }
    // Serialize Generic message
    serialized_message = generic_msg1.serialize();
    if (m_socket->send(serialized_message,
                       Generic::getMessageSize(download_msg1_len)) == -1) {
        delete[] serialized_message;
        return static_cast<int>(Return::SEND_FAILURE);
    }
    delete[] serialized_message;

    incrementCounter();

    // Receive message DownloadM2

    // Determine the size of the message
    size_t download_msg2_len = DownloadM2::getMessageSize();
    size_t generic_msg2_len = Generic::getMessageSize(download_msg2_len);
    // Allocate memory for the buffer to receive the Generic message
    serialized_message = new uint8_t[generic_msg2_len];
    // Receive the Generic message from the server
    if (m_socket->receive(serialized_message, generic_msg2_len) == -1) {
        delete[] serialized_message;
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }
    // Deserialize the received Generic message
    Generic generic_msg2 = Generic::deserialize(serialized_message, download_msg2_len);
    delete[] serialized_message;
    // Allocate memory for the plaintext buffer
    auto *plaintext = new uint8_t[download_msg2_len];
    // Decrypt the Generic message to obtain the serialized message
    if (generic_msg2.decrypt(m_session_key, plaintext) == -1) {
        return static_cast<int>(Return::DECRYPTION_FAILURE);
    }
    // Get message content
    DownloadM2 download_msg2 = DownloadM2::deserialize(plaintext);
    // Safely clean plaintext buffer
    OPENSSL_cleanse(plaintext, download_msg2_len);
    delete[] plaintext;
    // Check the counter value to prevent replay attacks
    if (m_counter != generic_msg2.getCounter()) {
        return static_cast<int>(Return::WRONG_COUNTER);
    }

    incrementCounter();

    // Check the received message code
    if (download_msg2.getMessageCode() == static_cast<uint8_t>(Error::FILE_NOT_FOUND)) {
        return static_cast<int>(Return::FILE_NOT_FOUND);
    }
    if (download_msg2.getMessageCode() != static_cast<uint8_t>(Message::DOWNLOAD_ACK)) {
        return static_cast<int>(Return::WRONG_MSG_CODE);
    }

    // Receive message DownloadM3+i

    // Open a file in write mode and init its information
    FileManager downloaded_file(filename, FileManager::OpenMode::WRITE);
    streamsize downloaded_file_size = download_msg2.getFileSize();
    downloaded_file.initFileInfo(downloaded_file_size);

    streamsize chunk_size = Config::CHUNK_SIZE;
    streamsize bytes_received = 0;

    // Receive each chunk of the file from the Server
    for (size_t i = 0; i < downloaded_file.getChunksNum(); i++) {
        // If the chunk is the last, set the appropriate size
        if (i == downloaded_file.getChunksNum() - 1) {
            chunk_size = downloaded_file.getLastChunkSize();
        }
        // Receive the message DownloadMi from the Server

        // Determine the size of the message
        size_t download_msg3i_len = DownloadMi::getMessageSize(chunk_size);
        size_t generic_msg3i_len = Generic::getMessageSize(download_msg3i_len);
        // Allocate memory for the buffer to receive the Generic message
        serialized_message = new uint8_t[generic_msg3i_len];
        // Receive the Generic message from the server
        if (m_socket->receive(serialized_message, generic_msg3i_len) == -1) {
            delete[] serialized_message;
            return static_cast<int>(Return::RECEIVE_FAILURE);
        }
        // Deserialize the received Generic message
        Generic generic_msg3i = Generic::deserialize(serialized_message, download_msg3i_len);
        delete[] serialized_message;
        // Allocate memory for the plaintext buffer
        plaintext = new uint8_t[download_msg3i_len];
        // Decrypt the Generic message to obtain the serialized message
        if (generic_msg3i.decrypt(m_session_key, plaintext) == -1) {
            return static_cast<int>(Return::DECRYPTION_FAILURE);
        }
        DownloadMi download_msg3i = DownloadMi::deserialize(plaintext, chunk_size);
        // Safely clean plaintext buffer
        OPENSSL_cleanse(plaintext, download_msg3i_len);
        delete[] plaintext;
        // Check the counter value to prevent replay attacks
        if (m_counter != generic_msg3i.getCounter()) {
            return static_cast<int>(Return::WRONG_COUNTER);
        }

        incrementCounter();

        // Check the received message code
        if (download_msg3i.getMessageCode() != static_cast<uint8_t>(Message::DOWNLOAD_CHUNK)) {
            return static_cast<int>(Return::WRONG_MSG_CODE);
        }
        // Write the current chunk in the file
        downloaded_file.writeChunk(download_msg3i.getFileChunk(), chunk_size);
        // Compute and show the progress to the user
        bytes_received += chunk_size;
        downloaded_file.getFileSize();
        // Calculate download progress percentage
        int progress_percentage = static_cast<int>(
                ((double)bytes_received / (double)downloaded_file_size) * 100);
        cout << "Client - Downloading: " << progress_percentage << "% complete" << endl;
    }

    // Return success code if the end of the function is reached
    return static_cast<int>(Return::SUCCESS);
}

int Client::run() {
    //LOGIN PHASE
    cout << "Client - Insert Username: ";
    cin >> m_username;
    string password;
    cout << "Client - Insert Password: ";
    cin >> password;

    // Check the username and password
    if (!FileManager::isStringValid(m_username) || !FileManager::isStringValid(password)) {
        cout << "Client - Invalid Username or Password!" << endl;
        return -1;
    }


    //SERVER CONNECTION
    // Construct the encrypted private key filename
    string private_key_file = "../resources/encrypted_private_keys/" + m_username + "_key.pem";

    // Open the encrypted private key file
    BIO *bio = BIO_new_file(private_key_file.c_str(), "r");
    if (!bio) {
        // Handle error if the key file cannot be opened
        cout << "Client - Wrong Username!" << endl;
        return -1;
    }

    // Read the encrypted private key using the provided password
    m_long_term_private_key = PEM_read_bio_PrivateKey(bio, 0, 0, (void *) password.c_str());
    BIO_free(bio);

    // Check if the password is correct
    if (!m_long_term_private_key) {
        cout << "Client - Wrong password!" << endl;
        return -1;
    }

    cout << "Client - Successful Authentication for " << m_username << endl;


    // Connect to the server
    try {
        SocketManager client_socket = SocketManager(Config::SERVER_IP, Config::SERVER_PORT);
    } catch (const exception &e) {
        cout << "Client - Connection to the server failed" << endl;
        return -1;
    }


    //AUTHENTICATION PHASE
    int result = authentication();
    // Check result

    //OPERATIONS PHASE (enter the loop)
    try {
        while (true) {
            // Display Operations Menu
            showMenu();

            cout << "User: " << m_username << endl;
            // Choose the operation code
            cout << "Client - Insert operation code: ";
            string operation_code_string;
            cin >> operation_code_string;


            // Check if the operation code format is valid
            while (!FileManager::isNumeric(operation_code_string)) {
                cout << "Client - Invalid operation code!\n" << endl;
                showMenu();
                cout << "Client - Insert operation code: ";
                cin >> operation_code_string;
            }

            // Execute the operation selected
            switch (stoi(operation_code_string)) {
                case 1: {
                    cout << "Client - List Files operation selected\n" << endl;
                    result = listRequest();
                    if (result != static_cast<int>(Return::SUCCESS)) {
                        cout << "List failed with error code " << result << endl;
                    }
                    break;
                }

                case 2: {
                    cout << "Client - Download File operation selected\n" << endl;
                    string filename;
                    cout << "Client - Insert the name of the file to download: ";
                    cin >> filename;
                    // Check if the filename is valid
                    while (!FileManager::isStringValid(filename)) {
                        cout << "Client - Insert the name of the file to download: ";
                        cin >> filename;
                    }
                    // Execute the download operation and check the result
                    result = downloadRequest(filename);
                    if (result == static_cast<int>(Return::SUCCESS)) {
                        cout << "Client - File " << filename << " downloaded successfully\n" << endl;
                    } else if (result == static_cast<int>(Return::FILE_ALREADY_EXISTS)) {
                        cout << "Client - File " << filename << " already exists\n" << endl;
                    } else if (result == static_cast<int>(Return::FILE_NOT_FOUND)) {
                        cout << "Client - File " << filename << " not found\n" << endl;
                    } else {
                        cout << "Client - Download failed with error code " << result << endl;
                    }
                    break;
                }

                case 3:
                    cout << "Client - Upload File operation selected\n" << endl;
                    break;

                case 4:
                    cout << "Client - Rename File operation selected\n" << endl;
                    break;

                case 5:
                    cout << "Client - Delete File operation selected\n" << endl;
                    break;
                case 6:
                    cout << "Client - Logout operation selected\n" << endl;
                    break;
                case 7:
                    return 1;

                default:
                    cout << "Client - Not-Existent operation code\n" << endl;
                    break;
            }
        }
    } catch (int error) {
        cout << "Client - Error detected! " << error << endl;
    }

    return 0;
}

/**
 * Increment the counter value or perform re-authentication if needed.
 * If the counter reaches the maximum value, re-authentication is triggered.
 * @throws int Return::LOGIN_FAILURE if re-authentication fails.
 */
void Client::incrementCounter() {
    // Check if re-authentication is needed
    if (m_counter == Config::MAX_COUNTER_VALUE) {
        // Perform re-authentication
        if (authentication() != static_cast<int>(Return::SUCCESS)) {
            throw static_cast<int>(Return::LOGIN_FAILURE);
        }
        m_counter = 0; // Reset counter after successful re-authentication
    } else {
        m_counter++; // Increment counter
    }
}

/**
 * Displays the Operation Menu options
 */
void Client::showMenu() {
    cout << "**MENU**\n"
            "* 1.list files\n"
            "* 2.download file\n"
            "* 3.upload\n"
            "* 4.rename\n"
            "* 5.delete\n"
            "* 6.logout\n"
            "* 7.exit\n" << endl;
}
