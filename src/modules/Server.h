#ifndef SECURE_CLOUD_STORAGE_SERVER_H
#define SECURE_CLOUD_STORAGE_SERVER_H

#include "SocketManager.h"
#include "Config.h"

class Server {

private:
    string m_username;
    uint32_t m_counter{};
    SocketManager *m_socket;
    unsigned char *m_session_key{};

    int authentication(); //francesco

    int listRequest(uint8_t *plaintext); //totore

    int downloadRequest(uint8_t *plaintext); //totore

    int uploadRequest(uint8_t *plaintext); //luca

    int renameRequest(uint8_t *plaintext); //francesco

    int deleteRequest(uint8_t *plaintext); //luca

    int logout(uint8_t *plaintext); //luca

    void incrementCounter(); //totore


public:
    Server(SocketManager *socket);

    ~Server();

    void run();
};


#endif //SECURE_CLOUD_STORAGE_SERVER_H
