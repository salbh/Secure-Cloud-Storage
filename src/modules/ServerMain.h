#ifndef SECURE_CLOUD_STORAGE_SERVERMAIN_H
#define SECURE_CLOUD_STORAGE_SERVERMAIN_H

#include <vector>
#include <thread>
#include "SocketManager.h"

class ServerMain {

    SocketManager* m_socket_manager;
    vector<thread> m_thread_pool;

public:
    ServerMain();

    ~ServerMain();

    SocketManager *getMSocketManager() const;

    static void serverSignalHandler(int signal);

    void emplaceThread(int socket_descriptor);
};


#endif //SECURE_CLOUD_STORAGE_SERVERMAIN_H
