#include <iostream>
#include <cstring>
#include <exception>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "SocketManager.h"


int SocketManager::initSocket(string ip_address, int port) {
    m_socket = socket(AF_INET, SOCK_STREAM, 0);

    return 0;
}


SocketManager::SocketManager(string ip_address, int port, int max_requests) {
    int res = initSocket(ip_address,port);

}

SocketManager::SocketManager() {

}


SocketManager::~SocketManager() {

}

int SocketManager::send() {
}

int SocketManager::receive() {

}

int SocketManager::accept() {

}