#include <iostream>
#include <filesystem>
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
#include "Upload.h"

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
    // Safely clean plaintext buffer
    OPENSSL_cleanse(serialized_message, simple_msg_len);
    // Serialize Generic message
    serialized_message = generic_msg1.serialize();
    if (m_socket->send(serialized_message,
                    Generic::getMessageSize(simple_msg_len)) == -1) {
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
    // Check the counter value to prevent replay attacks
    if (m_counter != generic_msg2.getCounter()) {
        return static_cast<int>(Return::WRONG_COUNTER);
    }
    ListM2 list_msg2 = ListM2::deserialize(plaintext);
    // Safely clean plaintext buffer
    OPENSSL_cleanse(plaintext, list_msg2_len);
    delete[] plaintext;

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
    // Check the counter value to prevent replay attacks
    if (m_counter != generic_msg3.getCounter()) {
        return static_cast<int>(Return::WRONG_COUNTER);
    }
    ListM3 list_msg3 = ListM3::deserialize(plaintext, list_size);
    // Safely clean plaintext buffer
    OPENSSL_cleanse(plaintext, list_msg2_len);
    delete[] plaintext;

    incrementCounter();

    // Check the received message code
    if (list_msg3.getMessageCode() != static_cast<uint8_t>(Message::LIST_RESPONSE)) {
        return static_cast<int>(Return::WRONG_MSG_CODE);
    }

    // Show the obtained list to the user
    cout << "----------- LIST -------------" << endl;
    istringstream file_list_stream(reinterpret_cast<char*>(list_msg3.getFileList()));
    string file_name;
    while (getline(file_list_stream, file_name, ',')) {
        cout << file_name << endl;
    }
    cout << "------------------------------" << endl;
    return static_cast<int>(Return::SUCCESS);
}


//-------------------------------------UPLOAD REQUEST-------------------------------------//

/**
 * Client side upload request operation
 * 1) Send an upload message request to the server specifying file name and file size(UploadM1 message type)
 * 2) Waits a response from the server indicating the success or failure of the upload request (SimpleMessage)
 * 3) Divides the file into chunks and sends each chunk to the server as an M3+i message (UploadMi Message)
 * 4) Waits for the final response from the server after sending all file chunks, indicating the overall success or
 * failure of the file upload (SimpleMessage)
 *
 * @param filename The name of the file to be uploaded
 * @return An integer value representing the success or failure of the upload process.
 */
int Client::uploadRequest(string filename) {
    // Open the file
    FileManager file_to_upload(filename, FileManager::OpenMode::READ);

    // Check the file size (0 of greater than 4GB)
    if (file_to_upload.getFileSize() == 0 || file_to_upload.getFileSize() > Config::MAX_FILE_SIZE) {
        cerr << "Client - Cannot Upload the File! File Empty or larger than 4GB" << endl;
        return static_cast<int>(Return::WRONG_FILE_SIZE);
    }


    // 1) Create the M1 message (Upload request specifying the file name and file size) and increment counter
    UploadM1 upload_msg1(filename, file_to_upload.getFileSize());
    uint8_t* serialized_message = upload_msg1.serializeUploadM1();

    // Determine the size of the plaintext and ciphertext
    size_t upload_msg1_len = UploadM1::getSizeUploadM1();

    // Create a Generic message with the current counter value
    Generic generic_msg1(m_counter);
    // Encrypt the serialized plaintext and init the GenericMessage fields
    if (generic_msg1.encrypt(m_session_key, serialized_message,static_cast<int>(upload_msg1_len)) == -1) {
        cout << "Client - Error during encryption" << endl;
        return static_cast<int>(Return::ENCRYPTION_FAILURE);
    }
    // Safely clean plaintext buffer
    OPENSSL_cleanse(serialized_message, Config::MAX_PACKET_SIZE);
    // Serialize and Send Generic message (UploadM1 message)
    serialized_message = generic_msg1.serialize();
    if (m_socket->send(serialized_message,Generic::getMessageSize(upload_msg1_len)) == -1) {
        return static_cast<int>(Return::SEND_FAILURE);
    }

    //Free the memory allocated for UploadM1 message
    delete[] serialized_message;

    // Increment counter against replay attack
    incrementCounter();


    // 2) Receive the result packet M2 message (success or failed request. Is a Simple Message)
    // Determine the size of the message to receive
    size_t upload_msg2_len = SimpleMessage::getMessageSize();

    // Allocate memory for the buffer to receive the Generic message
    serialized_message = new uint8_t[Generic::getMessageSize(upload_msg2_len)];
    if (m_socket->receive(serialized_message, upload_msg2_len) == -1) {
        delete[] serialized_message;
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }

    // Deserialize the received Generic message
    Generic generic_msg2 = Generic::deserialize(serialized_message, upload_msg2_len);
    delete[] serialized_message;
    // Allocate memory for the plaintext buffer
    auto *plaintext = new uint8_t[upload_msg2_len];
    // Decrypt the Generic message to obtain the serialized message
    if (generic_msg2.decrypt(m_session_key, plaintext) == -1) {
        return static_cast<int>(Return::DECRYPTION_FAILURE);
    }
    // Check the counter value to prevent replay attacks
    if (m_counter != generic_msg2.getCounter()) {
        return static_cast<int>(Return::WRONG_COUNTER);
    }
    // Deserialize the upload message 2 received (is a Simple Message )
    SimpleMessage upload_msg2 = SimpleMessage::deserialize(plaintext);
    // Safely clean plaintext buffer
    OPENSSL_cleanse(plaintext, upload_msg2_len);
    delete[] plaintext;

    // Increment counter against replay attack
    incrementCounter();

    // Check the received message code
    if (upload_msg2.getMessageCode() != static_cast<uint8_t>(Result::ACK)) {
        return static_cast<int>(Return::WRONG_MSG_CODE);
    }


    // 3) Create the M3+i messages (file chunk)
    // Determine the chunk size based on the file size and the number of chunks
    size_t chunk_size = file_to_upload.getFileSize() / file_to_upload.getChunksNum() ;
    // Allocate a buffer to store each file chunk
    uint8_t *chunk_buffer = new uint8_t [chunk_size];

    // Iterate all file chunks and send to the Server
    for (size_t i = 0; i < file_to_upload.getChunksNum(); ++i) {
        // Adjust the chunk size if is the last chunk
        if (i == file_to_upload.getChunksNum() - 1)
            chunk_size = file_to_upload.getLastChunkSize();

        // Read the next chunk from the file
        file_to_upload.readChunk(chunk_buffer,chunk_size);

        // Create the M3+i packet (UploadMi)
        UploadMi upload_msgi(chunk_buffer, chunk_size);
        serialized_message = upload_msgi.serializeUploadMi();

        // Determine the size of the plaintext and ciphertext
        size_t upload_msgi_len = UploadMi::getSizeUploadMi(chunk_size);

        Generic generic_msgi(m_counter);
        // Encrypt the serialized plaintext and init the GenericMessage fields
        if (generic_msgi.encrypt(m_session_key, serialized_message,static_cast<int>(upload_msgi_len)) == -1) {
            cout << "Client - Error during encryption" << endl;
            return static_cast<int>(Return::ENCRYPTION_FAILURE);
        }
        // Safely clean plaintext buffer
        OPENSSL_cleanse(serialized_message, upload_msgi_len);
        // Serialize Generic message
        serialized_message = generic_msgi.serialize();
        // Send the serialized GenericMessage to the server
        if (m_socket->send(serialized_message,Generic::getMessageSize(upload_msgi_len)) == -1) {
            return static_cast<int>(Return::SEND_FAILURE);
        }
        // Clean up memory used for serialization
        delete[] serialized_message;

        // Increment counter against replay attack
        incrementCounter();
    }

    // Safely clean chunk buffer
    OPENSSL_cleanse(chunk_buffer, chunk_size);


    // 4) Receive the final packet M3+i+1 message (success or failed file upload. Is a Simple Message)
    // Determine the size of the message to receive
    size_t upload_msgi1_len = SimpleMessage::getMessageSize();

    // Allocate memory for the buffer to receive the Generic message
    serialized_message = new uint8_t[Generic::getMessageSize(upload_msgi1_len)];
    if (m_socket->receive(serialized_message, upload_msgi1_len) == -1) {
        delete[] serialized_message;
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }

    // Deserialize the received Generic message
    Generic generic_msgi1 = Generic::deserialize(serialized_message, upload_msgi1_len);
    delete[] serialized_message;
    // Allocate memory for the plaintext buffer
    plaintext = new uint8_t[upload_msg2_len];
    // Decrypt the Generic message to obtain the serialized message
    if (generic_msgi1.decrypt(m_session_key, plaintext) == -1) {
        return static_cast<int>(Return::DECRYPTION_FAILURE);
    }
    // Check the counter value to prevent replay attacks
    if (m_counter != generic_msgi1.getCounter()) {
        return static_cast<int>(Return::WRONG_COUNTER);
    }
    // Deserialize the upload message 2 received (is a Simple Message )
    SimpleMessage upload_msg3i = SimpleMessage::deserialize(plaintext);
    // Safely clean plaintext buffer
    OPENSSL_cleanse(plaintext, upload_msgi1_len);
    delete[] plaintext;

    // Increment counter against replay attack
    incrementCounter();

    // Check the received message code
    if (upload_msg3i.getMessageCode() != static_cast<uint8_t>(Result::ACK)) {
        return static_cast<int>(Return::WRONG_MSG_CODE);
    }

    // Successful upload
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
                case 1:
                    cout << "Client - List Files operation selected\n" << endl;
                    result = listRequest();
                    if (result != static_cast<int>(Return::SUCCESS)) {
                        cout << "List failed with error code " << result << endl;
                    }
                    break;

                case 2:
                    cout << "Client - Download File operation selected\n" << endl;
                    break;

                case 3: {
                    cout << "Client - Upload File operation selected\n" << endl;
                    // Let the user insert the file name
                    string filename;
                    cout << "Client - Insert the name of the file to upload: ";
                    cin >> filename;
                    // Check if the filename is valid
                    if (!FileManager::isStringValid(filename)) {
                        cout << "Client - Invalid File Name" << endl;
                        continue;
                    }
                    // Check if the file exists and is a regular file
                    if (!std::filesystem::exists(filename) && !std::filesystem::is_regular_file(filename)) {
                        std::cout << "Client - File exists and is a regular file.\n";
                        continue;
                    }
                    // Execute the upload operation and check the result
                    result = uploadRequest(filename);
                    if (result != static_cast<int>(Return::SUCCESS))
                        cout << "Client - Upload failed with error code " << result << endl;
                    else
                        cout << "Client - File " << filename << " uploaded successfully" << endl;
                    break;
                }

                case 4:
                    cout << "Client - Rename File operation selected\n" << endl;
                    break;

                case 5:
                    cout << "Client - Delete File operation selected\n" << endl;
                    break;
                case 6:
                    cout << "Client - Logout operation selected\n" << endl;
                    break;

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
            "* 6.logout\n" << endl;
}


