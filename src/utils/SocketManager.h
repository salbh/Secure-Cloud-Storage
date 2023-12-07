#ifndef SECURE_CLOUD_STORAGE_SOCKETMANAGER_H
#define SECURE_CLOUD_STORAGE_SOCKETMANAGER_H

#include <string>

using namespace std;

class SocketManager {
    int m_socket;

public:
    SocketManager(string ip_address, int port, int max_request);
    ~SocketManager();

    int initSocket(string ip_address, int port);

};


#endif //SECURE_CLOUD_STORAGE_SOCKETMANAGER_H
