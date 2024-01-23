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
    DiffieHellman dh_instance;
    EVP_PKEY* client_ephemeral_key = dh_instance.generateEphemeralKey();

    uint8_t* serialized_dh_ephemeral_key = nullptr;
    int serialized_dh_ephemeral_key_length;
    if (dh_instance.serializeEphemeralKey(client_ephemeral_key, serialized_dh_ephemeral_key,
                                          serialized_dh_ephemeral_key_length) == -1) {
        EVP_PKEY_free(client_ephemeral_key);
        delete[] serialized_dh_ephemeral_key;
        return static_cast<int>(Return::AUTHENTICATION_FAILURE);
    }
    // Authentication M1 message
    size_t serialized_message_length = AuthenticationM1::getMessageSize();
    AuthenticationM1 authenticationM1(serialized_dh_ephemeral_key,
                                      serialized_dh_ephemeral_key_length,
                     m_username);
    uint8_t* serialized_message = authenticationM1.serialize();

    int result = m_socket->send(serialized_message, serialized_message_length);
    OPENSSL_cleanse(serialized_message, serialized_message_length);
    if (result == -1) {
        EVP_PKEY_free(client_ephemeral_key);
        delete[] serialized_dh_ephemeral_key;
        return static_cast<int>(Return::SEND_FAILURE);
    }
    cout << "Authentication M1 message sent to the server!" << endl;

    // Authentication M2 message
    serialized_message_length = SimpleMessage::getMessageSize();
    serialized_message = new uint8_t[serialized_message_length];
    result = m_socket->receive(serialized_message, serialized_message_length);

    if (result == -1) {
        delete[] serialized_message;
        EVP_PKEY_free(client_ephemeral_key);
        delete[] serialized_dh_ephemeral_key;
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }

    SimpleMessage simpleMessage = SimpleMessage::deserialize(serialized_message);
    OPENSSL_cleanse(serialized_message, serialized_message_length);
    if (simpleMessage.getMMessageCode() != static_cast<int>(Result::ACK)) {
        cout << "User " << m_username << " not found!" << endl;
        EVP_PKEY_free(client_ephemeral_key);
        delete[] serialized_dh_ephemeral_key;
        return static_cast<int>(Error::USERNAME_NOT_FOUND);
    }

    // AuthenticationM3 message
    size_t authenticationM3_length = AuthenticationM3::getMessageSize();
    serialized_message = new uint8_t[authenticationM3_length];
    result = m_socket->receive(serialized_message, authenticationM3_length);
    if (result != 0) {
        delete serialized_message;
        EVP_PKEY_free(client_ephemeral_key);
        delete[] serialized_dh_ephemeral_key;
        return static_cast<int>(Return::RECEIVE_FAILURE);
    }

    cout << "AuthenticationM3 message received from the server!" << endl;

    AuthenticationM3 authenticationM3 = AuthenticationM3::deserialize(serialized_message);
    OPENSSL_cleanse(serialized_message, serialized_message_length);

    EVP_PKEY* server_ephemeral_key = dh_instance.deserializeEphemeralKey(
            const_cast<uint8_t *>(authenticationM3.getMEphemeralKey()),
            authenticationM3.getMEphemeralKeyLen());

    uint8_t* shared_secret = nullptr;
    size_t shared_secret_length;
    result = dh_instance.deriveSharedSecret(client_ephemeral_key, server_ephemeral_key,
                                            shared_secret, shared_secret_length);
    EVP_PKEY_free(client_ephemeral_key);
    EVP_PKEY_free(server_ephemeral_key);
    if(result != 0) {
        OPENSSL_cleanse(shared_secret, shared_secret_length);
        delete[] serialized_dh_ephemeral_key;
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

    cout << "AuthenticationM3 - Session key generated!" << endl;

    int ephemeral_key_buffer_length = authenticationM3.getMEphemeralKeyLen() + serialized_dh_ephemeral_key_length;
    uint8_t* ephemeral_key_buffer = new uint8_t [ephemeral_key_buffer_length];
    memcpy(ephemeral_key_buffer, serialized_dh_ephemeral_key,
           serialized_dh_ephemeral_key_length);
    memcpy(ephemeral_key_buffer + serialized_dh_ephemeral_key_length, authenticationM3.getMEphemeralKey(),
           authenticationM3.getMEphemeralKeyLen());
    delete[] serialized_dh_ephemeral_key;

    unsigned char* digital_signature = nullptr;
    unsigned int digital_signature_length;
    DigitalSignatureManager digitalSignatureManager;
    digitalSignatureManager.generateDS(ephemeral_key_buffer, ephemeral_key_buffer_length,
                                       digital_signature, digital_signature_length,
                                       m_long_term_private_key);

    unsigned char *ciphertext = nullptr;
    m_counter = 0;
    unsigned char aad[sizeof(uint32_t)];
    memcpy(aad, &m_counter, Config::AAD_LEN);
    unsigned char tag[Config::AES_TAG_LEN];
    AesGcm aesGcm = AesGcm(m_session_key);
    int ciphertext_length = aesGcm.encrypt(digital_signature, digital_signature_length,
                                           aad, Config::AAD_LEN,
                                           ciphertext, tag);
    delete[] digital_signature;

    if(ciphertext_length == -1) {
        delete[] serialized_message;
        delete[] ciphertext;
        delete[] ephemeral_key_buffer;
        cerr << "AuthenticationM3 - Error during the encryption!" << endl;
        return static_cast<int>(Return::ENCRYPTION_FAILURE);
    }

    CertificateManager* certificateManager = CertificateManager::getInstance();
    X509* server_certificate = certificateManager->deserializeCertificate(
            const_cast<uint8_t *>(authenticationM3.getMSerializedCertificate()),
            authenticationM3.getMSerializedCertificateLen());
    if(!certificateManager->verifyCertificate(server_certificate)) {
        X509_free(server_certificate);
        delete[] ephemeral_key_buffer;
        delete[] ciphertext;
        return static_cast<int>(Return::AUTHENTICATION_FAILURE);
    }

    cout << "AuthenticationM3 - Server certificate verified!" << endl;

    EVP_PKEY* server_public_key = certificateManager->getPublicKey(server_certificate);
    X509_free(server_certificate);

    unsigned char* decrypted_signature = nullptr;
    int decrypted_signature_length = aesGcm.decrypt(
            const_cast<unsigned char *>(authenticationM3.getMEncryptedDigitalSignature()),
                                                    ENCRYPTED_SIGNATURE_LEN * sizeof(uint8_t),
            (unsigned char *) authenticationM3.getMAad(),
            Config::AAD_LEN, const_cast<unsigned char *>(authenticationM3.getMIv()),
            (unsigned char *) authenticationM3.getMTag(), decrypted_signature);
    if (decrypted_signature_length == -1) {
        delete[] serialized_message;
        delete[] decrypted_signature;
        delete[] ciphertext;
        delete[] ephemeral_key_buffer;
        cerr << "AuthenticationM3 - Error during the encryption!" << endl;
        return static_cast<int>(Return::ENCRYPTION_FAILURE);
    }

    bool isSignatureVerified = digitalSignatureManager.isDSverified(ephemeral_key_buffer, ephemeral_key_buffer_length,
                                                                    decrypted_signature,
                                                                    decrypted_signature_length,
                                                                    server_public_key);
    delete[] ephemeral_key_buffer;
    delete[] decrypted_signature;
    EVP_PKEY_free(server_public_key);
    if (!isSignatureVerified) {
        delete[] ciphertext;
        delete[] serialized_message;
        return static_cast<int>(Return::AUTHENTICATION_FAILURE);
    }

    cout << "AuthenticationM3 - Server Digital Signature verified!" << endl;

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

    cout << "Client - Successful Authentication for " << m_username << endl;

    //AUTHENTICATION PHASE
    int result = authenticationRequest();
    if(result != static_cast<int>(Return::AUTHENTICATION_SUCCESS)) {
        cout << "Authentication failed with error code: " << result << endl;
        return -1;
    } else{

    }

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
            "* 6.logout\n" << endl;
}
