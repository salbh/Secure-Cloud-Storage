#ifndef SECURE_CLOUD_STORAGE_SERVER_H
#define SECURE_CLOUD_STORAGE_SERVER_H

#include "SocketManager.h"
#include "Config.h"

class Server {

private:
    string m_username;
    uint32_t m_counter;
    SocketManager *m_socket;
    unsigned char m_session_key[Config::AES_KEY_LEN];

    int login();

    int listRequest(uint8_t *plaintext);

    int downloadRequest(uint8_t *plaintext);

    int uploadRequest(uint8_t *plaintext);

    int renameRequest(uint8_t *plaintext);

    int deleteRequest(uint8_t *plaintext);

    int logout(uint8_t *plaintext);

    void incrementCounter();


public:
    Server(SocketManager *socket);

    ~Server();

    void run();
};


#endif //SECURE_CLOUD_STORAGE_SERVER_H
