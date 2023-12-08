#ifndef SECURE_CLOUD_STORAGE_SOCKETMANAGER_H
#define SECURE_CLOUD_STORAGE_SOCKETMANAGER_H

#include <string>

using namespace std;

class SocketManager {

    int m_socket;

public:
    SocketManager(string server_ip, int server_port, int max_request);
    SocketManager(string server_ip, int server_port);
    ~SocketManager();

    int initSocket(string ip_address, int port, sockaddr_in server_address);
    int accept();
    int send(uint8_t *message_buffer, int message_buffer_size);
    int receive(uint8_t *message_buffer, int message_buffer_size);
};


#endif //SECURE_CLOUD_STORAGE_SOCKETMANAGER_H
