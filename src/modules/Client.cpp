#include <iostream>
#include <filesystem>
#include <thread>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
#include <sstream>
#include <iomanip>

#include "SocketManager.h"
#include "Client.h"
#include "FileManager.h"
#include "CodesManager.h"
#include "SimpleMessage.h"
#include "Generic.h"
#include "List.h"
#include "Download.h"
#include "Upload.h"
#include "Delete.h"
#include "DiffieHellman.h"
#include "Authentication.h"
#include "Hash.h"
#include "DigitalSignatureManager.h"
#include "AesGcm.h"
#include "CertificateManager.h"

Client::Client() = default;

Client::~Client() {

}

int Client::authenticationRequest() {
    // Create an instance of DiffieHellman for key exchange
    DiffieHellman dh_instance;

    // Generate a client's ephemeral key pair
    EVP_PKEY* client_ephemeral_key = dh_instance.generateEphemeralKey();

    // Serialize the client's ephemeral key for transmission
    uint8_t* serialized_client_ephemeral_key = nullptr;
    int serialized_client_ephemeral_key_length;
    if (dh_instance.serializeEphemeralKey(client_ephemeral_key, serialized_client_ephemeral_key,
                                          serialized_client_ephemeral_key_length) == -1) {
        // Clean up and return on serialization failure
        EVP_PKEY_free(client_ephemeral_key);
        delete[] serialized_client_ephemeral_key;
        return static_cast<int>(Return::AUTHENTICATION_FAILURE);
    }

    // Authentication M1 message
    size_t serialized_message_length = AuthenticationM1::getMessageSize();
    AuthenticationM1 authenticationM1(serialized_client_ephemeral_key,
                                      serialized_client_ephemeral_key_length,
                                      m_username);
    uint8_t* serialized_message = authenticationM1.serialize();

    // Send Authentication M1 message to the server
    int result = m_socket->send(serialized_message, serialized_message_length);
    OPENSSL_cleanse(serialized_message, serialized_message_length);
    if (result == -1) {
        // Clean up and return on send failure
        EVP_PKEY_free(client_ephemeral_key);
        delete[] serialized_client_ephemeral_key;
        return static_cast<int>(Return::SEND_FAILURE);
    }
    cout << "AuthenticationM1 message sent to the server!" << endl;

    // Authentication M2 message
    serialized_message_length = SimpleMessage::getMessageSize();
    serialized_message = new uint8_t[serialized_message_length];
    result = m_socket->receive(serialized_message, serialized_message_length);

    if (result == -1) {
        // Clean up and return on receive failure
        delete[] serialized_message;
        EVP_PKEY_free(client_ephemeral_key);
        delete[] serialized_client_ephemeral_key;
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }

    // Deserialize Authentication M2 message
    SimpleMessage simpleMessage = SimpleMessage::deserialize(serialized_message);
    OPENSSL_cleanse(serialized_message, serialized_message_length);
    if (simpleMessage.getMMessageCode() != static_cast<int>(Result::ACK)) {
        // Inform if the user is not found and return an error code
        cout << "User " << m_username << " not found!" << endl;
        EVP_PKEY_free(client_ephemeral_key);
        delete[] serialized_message;
        delete[] serialized_client_ephemeral_key;
        return static_cast<int>(Error::USERNAME_NOT_FOUND);
    }

    // Authentication M3 message
    size_t authenticationM3_length = AuthenticationM3::getMessageSize();
    serialized_message = new uint8_t[authenticationM3_length];
    result = m_socket->receive(serialized_message, authenticationM3_length);
    if (result != 0) {
        // Clean up and return on receive failure
        delete[] serialized_message;
        EVP_PKEY_free(client_ephemeral_key);
        delete[] serialized_client_ephemeral_key;
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }

    cout << "AuthenticationM3 message received from the server!" << endl;

    // Deserialize Authentication M3 message
    AuthenticationM3 authenticationM3 = AuthenticationM3::deserialize(serialized_message);
    OPENSSL_cleanse(serialized_message, serialized_message_length);

    // Deserialize server's ephemeral key from Authentication M3
    EVP_PKEY* server_ephemeral_key = dh_instance.deserializeEphemeralKey(
            const_cast<uint8_t *>(authenticationM3.getMEphemeralKey()),
            authenticationM3.getMEphemeralKeyLen());

    // Derive shared secret using DiffieHellman key exchange
    uint8_t* shared_secret = nullptr;
    size_t shared_secret_length;
    result = dh_instance.deriveSharedSecret(client_ephemeral_key, server_ephemeral_key,
                                            shared_secret, shared_secret_length);
    EVP_PKEY_free(client_ephemeral_key);
    EVP_PKEY_free(server_ephemeral_key);
    if(result != 0) {
        // Clean up and return on key derivation failure
        OPENSSL_cleanse(shared_secret, shared_secret_length);
        delete[] serialized_message;
        delete[] serialized_client_ephemeral_key;
        return static_cast<int>(Return::AUTHENTICATION_FAILURE);
    }

    // Generate session key using the derived shared secret
    unsigned char* session_key = nullptr;
    unsigned int session_key_length;
    Hash::generateSHA256(shared_secret, shared_secret_length, session_key,
                         session_key_length);

    // Copy the session key to the client's member variable
    memcpy(m_session_key, session_key, Config::AES_KEY_LEN);
    OPENSSL_cleanse(shared_secret, shared_secret_length);
    delete[] shared_secret;
    OPENSSL_cleanse(session_key, session_key_length);
    delete[] session_key;

    cout << "AuthenticationM3 - Session key generated!" << endl;

    // Check if counters are equal for Authentication M3
    m_counter = 0;
    if(!authenticationM3.checkCounter(m_counter)) {
        // Clean up and return on counter mismatch
        delete[] serialized_message;
        delete[] serialized_client_ephemeral_key;
        cerr << "AuthenticationM3 - The counters aren't equal!" << endl;
        return static_cast<int>(Return::WRONG_COUNTER);
    }

    // Decrypt the digital signature in Authentication M3
    AesGcm aesGcm = AesGcm(m_session_key);
    unsigned char* decrypted_signature = nullptr;
    int decrypted_signature_length = aesGcm.decrypt(
            const_cast<unsigned char *>(authenticationM3.getMEncryptedDigitalSignature()),
            ENCRYPTED_SIGNATURE_LEN * sizeof(uint8_t),
            (unsigned char *) authenticationM3.getMAad(),
            Config::AAD_LEN, const_cast<unsigned char *>(authenticationM3.getMIv()),
            (unsigned char *) authenticationM3.getMTag(), decrypted_signature);
    if (decrypted_signature_length == -1) {
        // Clean up and return on decryption failure
        delete[] serialized_message;
        delete[] decrypted_signature;
        delete[] serialized_client_ephemeral_key;
        cerr << "AuthenticationM3 - Error during the decryption!" << endl;
        return static_cast<int>(Return::DECRYPTION_FAILURE);
    }

    // Concatenate client's and server's ephemeral keys for digital signature verification
    int ephemeral_key_buffer_length = authenticationM3.getMEphemeralKeyLen() + serialized_client_ephemeral_key_length;
    uint8_t* ephemeral_key_buffer = new uint8_t [ephemeral_key_buffer_length];
    memcpy(ephemeral_key_buffer, serialized_client_ephemeral_key,
           serialized_client_ephemeral_key_length);
    memcpy(ephemeral_key_buffer + serialized_client_ephemeral_key_length, authenticationM3.getMEphemeralKey(),
           authenticationM3.getMEphemeralKeyLen());
    delete[] serialized_client_ephemeral_key;

    // Generate digital signature for concatenated ephemeral keys
    unsigned char* digital_signature = nullptr;
    unsigned int digital_signature_length;
    DigitalSignatureManager digitalSignatureManager;
    digitalSignatureManager.generateDS(ephemeral_key_buffer, ephemeral_key_buffer_length,
                                       digital_signature, digital_signature_length,
                                       m_long_term_private_key);

    // Retrieve server's certificate and verify it
    CertificateManager* certificateManager = CertificateManager::getInstance();
    X509* server_certificate = certificateManager->deserializeCertificate(
            const_cast<uint8_t *>(authenticationM3.getMSerializedCertificate()),
            authenticationM3.getMSerializedCertificateLen());
    if(!certificateManager->verifyCertificate(server_certificate)) {
        // Clean up and return on certificate verification failure
        X509_free(server_certificate);
        delete[] serialized_message;
        delete[] ephemeral_key_buffer;
        return static_cast<int>(Return::AUTHENTICATION_FAILURE);
    }

    cout << "AuthenticationM3 - Server certificate verified!" << endl;

    // Extract server's public key from the certificate
    EVP_PKEY* server_public_key = certificateManager->getPublicKey(server_certificate);
    X509_free(server_certificate);

    // Verify the digital signature using the server's public key
    bool isSignatureVerified = digitalSignatureManager.isDSverified(ephemeral_key_buffer, ephemeral_key_buffer_length,
                                                                    decrypted_signature,
                                                                    decrypted_signature_length, server_public_key);
    delete[] ephemeral_key_buffer;
    delete[] decrypted_signature;
    EVP_PKEY_free(server_public_key);
    if (!isSignatureVerified) {
        // Clean up and return on digital signature verification failure
        delete[] serialized_message;
        return static_cast<int>(Return::AUTHENTICATION_FAILURE);
    }

    cout << "AuthenticationM3 - Server Digital Signature verified!" << endl;

    // AuthenticationM4 message

    // Encrypt the decrypted signature for transmission in AuthenticationM4
    unsigned char *ciphertext = nullptr;
    incrementCounter();
    unsigned char aad[sizeof(uint32_t)];
    memcpy(aad, &m_counter, Config::AAD_LEN);
    unsigned char tag[Config::AES_TAG_LEN];
    int ciphertext_length = aesGcm.encrypt(digital_signature, ENCRYPTED_SIGNATURE_LEN * sizeof(uint8_t),
                                           aad, Config::AAD_LEN,
                                           ciphertext, tag);
    delete[] digital_signature;

    if(ciphertext_length == -1) {
        // Clean up and return on encryption failure
        delete[] serialized_message;
        delete[] ciphertext;
        cerr << "AuthenticationM4 - Error during the encryption!" << endl;
        return static_cast<int>(Return::ENCRYPTION_FAILURE);
    }

    // Authentication M4 message
    serialized_message_length = AuthenticationM4::getMessageSize();
    AuthenticationM4 authenticationM4(aesGcm.getIV(), aad, tag, ciphertext);
    serialized_message = authenticationM4.serialize();
    result = m_socket->send(serialized_message, serialized_message_length);

    OPENSSL_cleanse(serialized_message, serialized_message_length);
    delete[] ciphertext;

    if (result == -1) {
        // Return on send failure
        return static_cast<int>(Return::SEND_FAILURE);
    }
    cout << "AuthenticationM4 message sent to the server!" << endl;

    // AuthenticationM5
    serialized_message_length = Generic::getMessageSize(Config::MAX_PACKET_SIZE);
    serialized_message = new uint8_t [serialized_message_length];
    incrementCounter();
    result = m_socket->receive(serialized_message, serialized_message_length);
    if (result != 0) {
        // Clean up and return on receive failure
        delete[] serialized_message;
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }

    cout << "AuthenticationM5 message received from the Server" << endl;

    // Deserialize AuthenticationM5 message
    Generic generic_message = Generic::deserialize(serialized_message,
                                                   Config::MAX_PACKET_SIZE);
    delete[] serialized_message;

    // Allocate memory for the plaintext
    auto *plaintext = new uint8_t[Config::MAX_PACKET_SIZE];

    // Decrypt the received ciphertext
    if (generic_message.decrypt(m_session_key, plaintext) == -1) {
        cerr << "AuthenticationM5 - Error during the decryption!" << endl;
        return static_cast<int>(Return::DECRYPTION_FAILURE);
    }

    // Check the counter value to prevent replay attacks
    if (m_counter != generic_message.getCounter()) {
        // Return on counter mismatch
        throw static_cast<int>(Return::WRONG_COUNTER);
    }

    // Check the result in the plaintext to ensure successful authentication
    if (static_cast<Result>(plaintext[0]) != Result::ACK) {
        delete[] plaintext;
        cerr << "AuthenticationM5 - " << "Client Signature not verified!" << endl;
        return static_cast<int>(Return::AUTHENTICATION_FAILURE);
    }

    // Clean up and reset the counter
    delete[] plaintext;
    m_counter = 0;
    cout << "AuthenticationM5 - " << "Client Signature verified!" << endl;

    // Return success code after successful authentication
    return static_cast<int>(Return::AUTHENTICATION_SUCCESS);
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
        if (downloaded_file.writeChunk(download_msg3i.getFileChunk(), chunk_size) == -1) {
            return static_cast<int>(Return::WRITE_CHUNK_FAILURE);
        }
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
        cout << "Client - UploadRequest() - Cannot Upload the File! File Empty or larger than 4GB" << endl;
        return static_cast<int>(Return::WRONG_FILE_SIZE);
    }


    // 1) Create the M1 message (Upload request specifying the file name and file size) and increment counter
    UploadM1 upload_msg1(filename, file_to_upload.getFileSize());
    uint8_t* serialized_message = upload_msg1.serializeUploadM1();

    // Determine the size of the message
    size_t upload_msg1_len = UploadM1::getSizeUploadM1();

    // Create a Generic message with the current counter value
    Generic generic_msg1(m_counter);
    // Encrypt the serialized plaintext and init the Generic message fields
    if (generic_msg1.encrypt(m_session_key, serialized_message,static_cast<int>(upload_msg1_len)) == -1) {
        cout << "Client - uploadRequest() - Error during encryption" << endl;
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


    // 2) Receive the result message M2 message (success or failed request. Simple Message) and increment counter
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
    // Deserialize the upload message 2 received (Simple Message)
    SimpleMessage upload_msg2 = SimpleMessage::deserialize(plaintext);
    // Safely clean plaintext buffer
    OPENSSL_cleanse(plaintext, upload_msg2_len);
    delete[] plaintext;

    // Increment counter against replay attack
    incrementCounter();

    // Check the received message code
    if (upload_msg2.getMMessageCode() != static_cast<uint8_t>(Result::ACK)) {
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
        UploadMi upload_msg3i(chunk_buffer, chunk_size);
        serialized_message = upload_msg3i.serializeUploadMi();

        // Determine the size of the plaintext and ciphertext
        size_t upload_msg3i_len = UploadMi::getSizeUploadMi(chunk_size);

        Generic generic_msg3i(m_counter);
        // Encrypt the serialized plaintext and init the GenericMessage fields
        if (generic_msg3i.encrypt(m_session_key, serialized_message,static_cast<int>(upload_msg3i_len)) == -1) {
            cout << "Client - uploadRequest() - Error during encryption" << endl;
            return static_cast<int>(Return::ENCRYPTION_FAILURE);
        }
        // Safely clean plaintext buffer
        OPENSSL_cleanse(serialized_message, upload_msg3i_len);
        // Serialize Generic message
        serialized_message = generic_msg3i.serialize();
        // Send the serialized Generic message to the server
        if (m_socket->send(serialized_message,Generic::getMessageSize(upload_msg3i_len)) == -1) {
            return static_cast<int>(Return::SEND_FAILURE);
        }
        // Clean up memory used for serialization
        delete[] serialized_message;

        // Increment counter against replay attack
        incrementCounter();
    }

    // Safely clean chunk buffer
    OPENSSL_cleanse(chunk_buffer, chunk_size);


    // 4) Receive the final packet M3+i+1 message (success or failed file upload. Simple Message)
    // Determine the size of the message to receive
    size_t upload_msg3i1_len = SimpleMessage::getMessageSize();

    // Allocate memory for the buffer to receive the Generic message
    serialized_message = new uint8_t[Generic::getMessageSize(upload_msg3i1_len)];
    if (m_socket->receive(serialized_message, upload_msg3i1_len) == -1) {
        delete[] serialized_message;
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }

    // Deserialize the received Generic message
    Generic generic_msg3i1 = Generic::deserialize(serialized_message, upload_msg3i1_len);
    delete[] serialized_message;
    // Allocate memory for the plaintext buffer
    plaintext = new uint8_t[upload_msg2_len];
    // Decrypt the Generic message to obtain the serialized message
    if (generic_msg3i1.decrypt(m_session_key, plaintext) == -1) {
        return static_cast<int>(Return::DECRYPTION_FAILURE);
    }
    // Check the counter value to prevent replay attacks
    if (m_counter != generic_msg3i1.getCounter()) {
        return static_cast<int>(Return::WRONG_COUNTER);
    }
    // Deserialize the upload message 2 received (Simple Message)
    SimpleMessage upload_msg3i1 = SimpleMessage::deserialize(plaintext);
    // Safely clean plaintext buffer
    OPENSSL_cleanse(plaintext, upload_msg3i1_len);
    delete[] plaintext;

    // Increment counter against replay attack
    incrementCounter();

    // Check the received message code
    if (upload_msg3i1.getMMessageCode() != static_cast<uint8_t>(Result::ACK)) {
        return static_cast<int>(Return::WRONG_MSG_CODE);
    }

    // Successful upload
    return static_cast<int>(Return::SUCCESS);
}


/**
 * Client side logout request operation
 * 1) Send a logout message request to the server (SimpleMessage)
 * 2) Waits a response from the server indicating the success or failure of the logout request (SimpleMessage)
 * @return An integer value representing the success or failure of the logout process.
 */
int Client::logoutRequest() {
    // 1) Create the Logout M1 message (Logout request. Simple Message) and increment counter

    size_t logout_msg1_len = SimpleMessage::getMessageSize();

    SimpleMessage logout_msg1(static_cast<uint8_t>(Message::LOGOUT_REQUEST));
    uint8_t* serialized_message = logout_msg1.serialize();

    // Determine the size of the message


    // Create a Generic message with the current counter value
    Generic generic_msg1(m_counter);
    // Encrypt the serialized plaintext and init the Generic message fields
    if (generic_msg1.encrypt(m_session_key, serialized_message,static_cast<int>(logout_msg1_len)) == -1) {
        cout << "Client - logoutRequest() - Error during encryption" << endl;
        return static_cast<int>(Return::ENCRYPTION_FAILURE);
    }
    // Serialize and Send Generic message (UploadM1 message)
    serialized_message = generic_msg1.serialize();
    if (m_socket->send(serialized_message,Generic::getMessageSize(logout_msg1_len)) == -1) {
        delete[] serialized_message;
        return static_cast<int>(Return::SEND_FAILURE);
    }

    //Free the memory allocated for LogoutM1 message
    delete[] serialized_message;

    // Increment counter against replay attack
    incrementCounter();


    // 2) Receive the result Logout M2 message (success or failed Logout request. Simple Message)
    // Determine the size of the message to receive
    size_t logout_msg2_len = SimpleMessage::getMessageSize();
    size_t generic_msg2_len = Generic::getMessageSize(logout_msg2_len);
    // Allocate memory for the buffer to receive the Generic message
    serialized_message = new uint8_t[generic_msg2_len];
    if (m_socket->receive(serialized_message, generic_msg2_len) == -1) {
        delete[] serialized_message;
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }

    // Deserialize the received Generic message
    Generic generic_msg2 = Generic::deserialize(serialized_message, logout_msg2_len);
    delete[] serialized_message;
    // Allocate memory for the plaintext buffer
    auto *plaintext = new uint8_t[logout_msg2_len];
    // Decrypt the Generic message to obtain the serialized message
    if (generic_msg2.decrypt(m_session_key, plaintext) == -1) {
        return static_cast<int>(Return::DECRYPTION_FAILURE);
    }
    // Check the counter value to prevent replay attacks
    if (m_counter != generic_msg2.getCounter()) {
        return static_cast<int>(Return::WRONG_COUNTER);
    }
    // Deserialize the logout message 2 received (Simple Message)
    SimpleMessage logout_msg2 = SimpleMessage::deserialize(plaintext);
    // Safely clean plaintext buffer
    OPENSSL_cleanse(plaintext, logout_msg2_len);
    delete[] plaintext;

    // Check the received message code
    if (logout_msg2.getMMessageCode() != static_cast<uint8_t>(Result::ACK)) {
        return static_cast<int>(Return::WRONG_MSG_CODE);
    }

    cout << "Server - Logout successful" << endl;
    // Successful logout
    return static_cast<int>(Return::SUCCESS);
}


/**
 * Client side delete request operation
 * 1) Send a delete message request to the server specifying file name (Delete message type)
 * 2) Waits a response from the server asking the confirmation (SimpleMessage)
 * 3) Send the delete confirmation message to the server (SimpleMessage "DELETE_CONFIRM") or Abort the operation
 * 4) Waits for the final response from the server, indicating the overall success or failure
 * of the file delete (SimpleMessage)
 *
 * @param filename The name of the file to be deleted
 * @return An integer value representing the success or failure of the upload process.
 */
int Client::deleteRequest(string filename) {
    // 1) Create the Delete M1 message (Delete request specifying the file name) and increment counter
    Delete delete_msg1 = Delete(filename);
    uint8_t* serialized_message = delete_msg1.serialize();

    // Determine the size of the message
    size_t delete_msg1_len = Delete::getMessageSize();

    // Create a Generic message with the current counter value
    Generic generic_msg1(m_counter);
    // Encrypt the serialized plaintext and init the Generic message fields
    if (generic_msg1.encrypt(m_session_key, serialized_message,static_cast<int>(delete_msg1_len)) == -1) {
        cout << "Client - deleteRequest() - Error during encryption" << endl;
        return static_cast<int>(Return::ENCRYPTION_FAILURE);
    }
    // Serialize and Send Generic message (UploadM1 message)
    serialized_message = generic_msg1.serialize();
    if (m_socket->send(serialized_message,Generic::getMessageSize(delete_msg1_len)) == -1) {
        return static_cast<int>(Return::SEND_FAILURE);
    }

    //Free the memory allocated for UploadM1 message
    delete[] serialized_message;

    // Increment counter against replay attack
    incrementCounter();


    // 2) Receive the Delete M2 message (Delete Ask confirmation message. Simple Message)
    // Determine the size of the message to receive
    size_t delete_msg2_len = SimpleMessage::getMessageSize();
    size_t generic_msg2_len = Generic::getMessageSize(delete_msg2_len);
    // Allocate memory for the buffer to receive the Generic message
    serialized_message = new uint8_t[generic_msg2_len];
    if (m_socket->receive(serialized_message, generic_msg2_len) == -1) {
        delete[] serialized_message;
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }

    // Deserialize the received Generic message
    Generic generic_msg2 = Generic::deserialize(serialized_message, delete_msg2_len);
    delete[] serialized_message;
    // Allocate memory for the plaintext buffer
    auto *plaintext = new uint8_t[delete_msg2_len];
    // Decrypt the Generic message to obtain the serialized message
    if (generic_msg2.decrypt(m_session_key, plaintext) == -1) {
        return static_cast<int>(Return::DECRYPTION_FAILURE);
    }
    // Check the counter value to prevent replay attacks
    if (m_counter != generic_msg2.getCounter()) {
        return static_cast<int>(Return::WRONG_COUNTER);
    }
    // Deserialize the delete message 2 received (Simple Message)
    SimpleMessage delete_msg2 = SimpleMessage::deserialize(plaintext);
    // Safely clean plaintext buffer
    OPENSSL_cleanse(plaintext, delete_msg2_len);
    delete[] plaintext;

    // Increment counter against replay attack
    incrementCounter();

    // Check the received message code
    if (delete_msg2.getMMessageCode() != static_cast<uint8_t>(Message::DELETE_ASK)) {
        return static_cast<int>(Return::WRONG_MSG_CODE);
    }


    // Let the user insert the delete confirmation
    string confirmation_code;
    cout << "Client - deleteRequest() - Do you really want to delete " << filename << "?\n" << endl;
    cout << "1. Yes"
            "2. No\n"
            "Insert Command Code: " << endl;
    cin >> confirmation_code;
    // Check if the confirmation string is valid
    if (!FileManager::isNumeric(confirmation_code) || confirmation_code != "1" || confirmation_code != "2") {
        cout << "Client - deleteRequest() - Error Delete Confirm Code" << endl;
        return static_cast<int>(Return::WRONG_DELETE_CONFIRM);
    }

    //Delete Confirm OK
    if (confirmation_code == "1") {
        // 3) Create the Delete M3 message (Delete Confirmation. SimpleMessage) and increment counter
        SimpleMessage delete_msg3 = SimpleMessage(static_cast<uint8_t>(Message::DELETE_CONFIRM));
        serialized_message = delete_msg3.serialize();

        // Determine the size of the message
        size_t delete_msg3_len = SimpleMessage::getMessageSize();

        // Create a Generic message with the current counter value
        Generic generic_msg3(m_counter);
        // Encrypt the serialized plaintext and init the Generic message fields
        if (generic_msg3.encrypt(m_session_key, serialized_message,static_cast<int>(delete_msg3_len)) == -1) {
            cout << "Client - deleteRequest() - Error during encryption" << endl;
            return static_cast<int>(Return::ENCRYPTION_FAILURE);
        }
        // Serialize and Send Generic message (SimpleMessage)
        serialized_message = generic_msg3.serialize();
        if (m_socket->send(serialized_message,Generic::getMessageSize(delete_msg3_len)) == -1) {
            return static_cast<int>(Return::SEND_FAILURE);
        }

        //Free the memory allocated for UploadM1 message
        delete[] serialized_message;

        // Increment counter against replay attack
        incrementCounter();


        // 4) Receive the final Delete M4 message (success or failed file deletion. Simple Message)
        // Determine the size of the message to receive
        size_t delete_msg4_len = SimpleMessage::getMessageSize();

        // Allocate memory for the buffer to receive the Generic message
        serialized_message = new uint8_t[Generic::getMessageSize(delete_msg4_len)];
        if (m_socket->receive(serialized_message, Generic::getMessageSize(delete_msg4_len)) == -1) {
            delete[] serialized_message;
            return static_cast<int>(Return::RECEIVE_FAILURE);
        }

        // Deserialize the received Generic message
        Generic generic_msg4 = Generic::deserialize(serialized_message, delete_msg4_len);
        delete[] serialized_message;
        // Allocate memory for the plaintext buffer
        plaintext = new uint8_t[delete_msg4_len];
        // Decrypt the Generic message to obtain the serialized message
        if (generic_msg4.decrypt(m_session_key, plaintext) == -1) {
            return static_cast<int>(Return::DECRYPTION_FAILURE);
        }

        // Check the counter value to prevent replay attacks
        if (m_counter != generic_msg4.getCounter()) {
            return static_cast<int>(Return::WRONG_COUNTER);
        }

        // Deserialize the message received (Simple Message)
        SimpleMessage delete_msg4 = SimpleMessage::deserialize(plaintext);
        // Safely clean plaintext buffer
        OPENSSL_cleanse(plaintext, delete_msg4_len);
        delete[] plaintext;

        // Increment counter against replay attack
        incrementCounter();

        // Check the received message code
        if (delete_msg4.getMMessageCode() != static_cast<uint8_t>(Result::ACK)) {
            return static_cast<int>(Return::WRONG_MSG_CODE);
        }
    }

    else {
        cout << "Client - deleteRequest() - Delete Aborted!" << endl;
        return static_cast<int>(Return::NO_DELETE_CONFIRM);
    }


    // Successful delete
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

    // Connect to the server
    try {
        m_socket = new SocketManager(Config::SERVER_IP, Config::SERVER_PORT);
    } catch (const exception &e) {
        cout << "Client - Connection to the server failed" << endl;
        return -1;
    }

    //AUTHENTICATION PHASE
    int result = authenticationRequest();
    if(result != static_cast<int>(Return::AUTHENTICATION_SUCCESS)) {
        cout << "Authentication failed with error code: " << result << endl;
        return -1;
    }
    cout << "Client - Successful Authentication for " << m_username << endl;
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
                        std::cout << "Client - File exists or is not a regular file.\n";
                        continue;
                    }
                    // Execute the upload operation and check the result
                    result = uploadRequest(filename);
                    if (result != static_cast<int>(Return::SUCCESS))
                        cout << "Client - Upload failed with error code " << result << endl;
                    else
                        cout << "Client - File " << filename << " uploaded successfully\n" << endl;
                    break;
                }

                case 4:
                    cout << "Client - Rename File operation selected\n" << endl;
                    break;


                case 5: {
                    cout << "Client - Delete File operation selected\n" << endl;
                    // Let the user insert the file name
                    string filename;
                    cout << "Client - Insert the name of the file to delete: ";
                    cin >> filename;

                    // Check if the filename is valid
                    if (!FileManager::isStringValid(filename)) {
                        cout << "Client - Invalid File Name" << endl;
                        continue;
                    }
                    // Check if the file exists and is a regular file
                    string file_path = "../data/" + m_username + "/" + filename;
                    if (!FileManager::isFilePresent(file_path)) {
                        std::cout << "Client - File does not exists or is not a regular file.\n";
                        continue;
                    }
                    // Execute the upload operation and check the result
                    result = deleteRequest(filename);
                    if (result != static_cast<int>(Return::SUCCESS))
                        cout << "Client - Delete failed with error code " << result << endl;
                    else
                        cout << "Client - File " << filename << " Deleted successfully\n" << endl;


                    break;
                }
                case 6: {
                    cout << "Client - Logout operation selected\n" << endl;
                    // Execute the logout operation and check the result
                    result = logoutRequest();
                    if (result != static_cast<int>(Return::SUCCESS))
                        cout << "Client - Logout failed with error code " << result << endl;
                    else
                        cout << "Client - User " << m_username << " Logout Successful!\n" << endl;
                    break;
                  
                case 7:
                    return 1;
                }

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
 * Increment the counter value or perform re-authenticationRequest if needed.
 * If the counter reaches the maximum value, re-authenticationRequest is triggered.
 * @throws int Return::AUTHENTICATION_FAILURE if re-authenticationRequest fails.
 */
void Client::incrementCounter() {
    // Check if re-authenticationRequest is needed
    if (m_counter == Config::MAX_COUNTER_VALUE) {
        // Perform re-authenticationRequest
        if (authenticationRequest() != static_cast<int>(Return::SUCCESS)) {
            throw static_cast<int>(Return::AUTHENTICATION_FAILURE);
        }
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


