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
    SocketManager *m_socket;
    unsigned char *m_session_key;
    EVP_PKEY* m_long_term_private_key;

    int authentication();
    int listRequest();
    int uploadRequest(string filename);
    int logoutRequest();
    int deleteRequest(string filename);

    void incrementCounter();

public:
    Client();
    ~Client();

    int run();
    void showMenu();

    /**
     * FRANCESCO: authentication() e rename()
     * TOTORE: download() e list()
     * LUCA: upload(), logout() e remove()
     */
    void checkCounterValue();

    void checkCounterValue(Generic generic_message);
};


#endif //SECURE_CLOUD_STORAGE_CLIENT_H
