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
    int send();
    int receive();
    int accept();

};


#endif //SECURE_CLOUD_STORAGE_SOCKETMANAGER_H
