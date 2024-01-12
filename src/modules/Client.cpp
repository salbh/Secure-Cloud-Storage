#include <iostream>
#include <cstring>
#include <thread>
#include <arpa/inet.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "SocketManager.h"
#include "Client.h"
#include "FileManager.h"


Client::Client() =default;

Client::~Client() {

}


int Client::run() {
    //LOGIN PHASE
    cout << "Client - Insert Username: ";
    cin >> m_username;
    string password;
    cout << "Client - Insert Password: ";
    cin >> password;

    // Check the username and password
    if(!FileManager::isStringValid(m_username) || !FileManager::isStringValid(password)) {
        cerr << "Client - Invalid Username or Password!" << endl;
        return 1;
    }


    //SERVER CONNECTION
    // Construct the encrypted private key filename
    string private_key_file = "../resources/encrypted_private_keys/" + m_username + "_key.pem";

    // Open the encrypted private key file
    BIO *bio = BIO_new_file(private_key_file.c_str(), "r");
    if (!bio) {
        // Handle error if the key file cannot be opened
        cerr << "Client - Wrong Username!" << endl;
        return 1;
    }

    // Read the encrypted private key using the provided password
    m_long_term_private_key = PEM_read_bio_PrivateKey(bio, 0, 0, (void *) password.c_str());
    BIO_free(bio);

    // Check if the password is correct
    if (!m_long_term_private_key) {
        cerr << "Client - Wrong password!" << endl;
        return 1;
    }

    cout << "Client - Successful Authentication for " << m_username << endl;

    // Connect to the server
    try {
    SocketManager client_socket = SocketManager("localhost", 5000);
    } catch (const exception& e) {
        cerr << "Client - Connection to the server failed" << endl;
        return -1;
    }


    //AUTHENTICATION PHASE


    //OPERATIONS PHASE (enter the loop)
    try {
        while (1) {
            // Display Operations Menu
            showMenu();

            cout << "User: " << m_username << endl;
            // Choose the operation code
            cout << "Client - Insert operation code: ";
            string operation_code_string;
            cin >> operation_code_string;


            // Check if the operation code format is valid
            if (!FileManager::isStringValid(operation_code_string)){
                cerr << "Client - Invalid operation code!" << endl;
                return 1;
            }

            // Execute the operation selected
            switch (stoi(operation_code_string)) {
                case 1:
                    cout << "Client - List Files operation selected\n" << endl;
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
        cerr << "Client - Error detected! " << error << endl;
    }

    return 0;
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
