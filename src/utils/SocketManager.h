#ifndef SECURE_CLOUD_STORAGE_SOCKETMANAGER_H
#define SECURE_CLOUD_STORAGE_SOCKETMANAGER_H

#include <string>

using namespace std;

class SocketManager {

    int m_listening_socket;
    int m_socket;

public:
    SocketManager(const string& server_ip, int server_port, int max_request);
    SocketManager(const string& server_ip, int server_port);
    SocketManager(int socket_descriptor);
    ~SocketManager();

    int initSocket(const string &ip_address, int port, sockaddr_in& server_address, bool b);
    int accept();
    int send(uint8_t *message_buffer, size_t message_buffer_size);
    int receive(uint8_t *message_buffer, size_t message_buffer_size);
    void shutdown();
};


#endif //SECURE_CLOUD_STORAGE_SOCKETMANAGER_H
