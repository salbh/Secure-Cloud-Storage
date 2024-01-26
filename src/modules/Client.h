#ifndef SECURE_CLOUD_STORAGE_CLIENT_H
#define SECURE_CLOUD_STORAGE_CLIENT_H

#include <iostream>
#include <cstring>
#include <chrono>
#include <thread>
#include <arpa/inet.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "SocketManager.h"
#include "Config.h"
#include "Generic.h"


class Client {

    string m_username;
    uint32_t m_counter;
    SocketManager* m_socket;
    unsigned char m_session_key[Config::AES_KEY_LEN];
    EVP_PKEY* m_long_term_private_key;

    int authenticationRequest();
    int listRequest();
    int downloadRequest(const string& filename);
    int uploadRequest(string filename);
    int renameRequest(string file_name, string new_file_name);
    int logoutRequest();
    int deleteRequest(string filename);

    void incrementCounter();

public:
    Client();
    ~Client();

    int run();
    void showMenu();
};


#endif //SECURE_CLOUD_STORAGE_CLIENT_H
