#include <iostream>
#include <cstring>
#include <exception>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "SocketManager.h"


int SocketManager::initSocket(string ip_address, int port, sockaddr_in server_address) {

    //socket creation
    m_socket = socket(AF_INET, SOCK_STREAM, 0);

    //socket initialization (address creation)
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    inet_pton(AF_INET, ip_address.c_str(), &server_address.sin_addr);

    return m_socket;
}

/**
 * Server socket constructor
 * @param ip_address of the server
 * @param port of the server
 * @param max_requests max number of clients simultaneously waiting
 */
SocketManager::SocketManager(string ip_address, int port, int max_requests) {

    sockaddr_in server_address;

    //create and check the socket
    if (initSocket(ip_address, port, server_address) == -1) {
        cerr << "SocketManager - Error during socket creation!" << endl;
    }

    //binding the socket to an address
    if (bind(m_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) {
        cerr << "SocketManager - Error while binding socket!" << endl;
    }

    //opening the socket for requests listening
    if (listen(m_socket, max_requests) == -1) {
        cerr << "SocketManager - Error while opening the socket!" << endl;
    }


}

SocketManager::SocketManager() {
}


SocketManager::~SocketManager() {
}

int SocketManager::send() {
    return 0;
}

int SocketManager::receive() {
    return 0;
}

int SocketManager::accept() {
    return 0;
}