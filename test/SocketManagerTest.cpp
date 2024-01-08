#include <iostream>
#include <cstring>
#include <chrono>
#include <thread>
#include <arpa/inet.h>

#include <csignal>

#include "SocketManager.h"
#include "Config.h"

#define MSG "test\0"
#define MSG_SIZE 5

using namespace std;

struct TestMessage {

    unsigned char m_iv[5];
    unsigned char m_aad[2];
    unsigned char m_tag[5];
    uint8_t m_type;
    char m_text[20];

    TestMessage() {}

    TestMessage(unsigned char *iv, unsigned char *aad, unsigned char *tag, uint8_t type, string text) {

        memcpy(this->m_iv, iv, Config::IV_LEN);
        memcpy(this->m_aad, aad, Config::AAD_LEN);
        memcpy(this->m_tag, tag, Config::AES_TAG_LEN);
        this->m_type = type;

        memset(this->m_text, 0, sizeof(this->m_text));
        strcpy(this->m_text, text.c_str());

    }

    uint8_t *serialize() const {

        uint8_t *buffer = new uint8_t[TestMessage::getSize()];

        size_t position = 0;
        memcpy(buffer, m_iv, 5 * sizeof(uint8_t));
        position += 5 * sizeof(uint8_t);

        memcpy(buffer, m_aad, 2 * sizeof(uint8_t));
        position += 2 * sizeof(uint8_t);

        memcpy(buffer, m_tag, 5 * sizeof(uint8_t));
        position += 5 * sizeof(uint8_t);

        memcpy(buffer + position, &m_type, sizeof(uint8_t));
        position += sizeof(uint8_t);


        memcpy(buffer + position, m_text, 20 * sizeof(char));
        position += 20 * sizeof(char);

        return buffer;
    }

    static TestMessage deserialize(uint8_t *buffer) {

        TestMessage packet;

        size_t position = 0;
        memcpy(packet.m_iv, buffer, 5 * sizeof(uint8_t));
        position += 5 * sizeof(uint8_t);

        memcpy(packet.m_aad, buffer, 2 * sizeof(uint8_t));
        position += 2 * sizeof(uint8_t);

        memcpy(packet.m_tag, buffer, 5 * sizeof(uint8_t));
        position += 5 * sizeof(uint8_t);

        memcpy(&packet.m_type, buffer + position, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(packet.m_text, buffer + position, 20 * sizeof(char));
        position += 20 * sizeof(char);

        return packet;
    }

    static int getSize() {

        int size = 0;

        size += 5 * sizeof(uint8_t);
        size += 2 * sizeof(uint8_t);
        size += 5 * sizeof(uint8_t);
        size += sizeof(uint8_t);
        size += 20 * sizeof(char);

        return size;
    }

    void print() const {

        cout << "\nPACKET:" << endl;
        cout << "IV: " << m_iv << endl;
        cout << "AAD: " << m_aad << endl;
        cout << "TAG: " << m_tag << endl;
        cout << "TYPE: " << (int)m_type << endl;
        cout << "TEXT: " << m_text << endl;
    }
};



void server() {
    cout << "SERVER PART" << endl;
    SocketManager server_socket("localhost", 5000, 10);

    int server_socket_descriptor = server_socket.accept();
    if (server_socket_descriptor == -1)
        cout << "SocketManagerTest - Error on accept function" << endl;

    //send of the message
    for (int i = 0; i < 3; ++i) {
        uint8_t msg[MSG_SIZE];
        int msg_size = MSG_SIZE;

        server_socket.receive(msg, msg_size);
        cout << "SocketManagerTest - Msg Received: " << msg << endl;

        if (!strcmp((const char*)msg, MSG))
            cout << "SocketManagerTest - Stringa uguale" << endl;
    }

    //message parameters definition
    unsigned char* iv = (unsigned char*)"0123";
    unsigned char* aad = (unsigned char*)"1";
    unsigned char* tag = (unsigned char*)"4567";
    uint8_t type = 2;
    string text = "Socket Test Message";

    //message object creation
    TestMessage packet(iv, aad, tag, type, text);

    uint8_t* serialized_packet = packet.serialize();
    server_socket.send(serialized_packet, TestMessage::getSize());

    delete[] serialized_packet;
}


void client() {
    this_thread::sleep_for(chrono::seconds(2));
    SocketManager client_socket = SocketManager("localhost", 5000);
    cout << "CLIENT PART" << endl;

    uint8_t* msg = (uint8_t*)MSG;
    int msg_size = MSG_SIZE;

    for (int i = 0; i < 3; ++i) {
        cout << "send message: " << msg << endl;
        client_socket.send(msg, msg_size);
    }

    uint8_t serialized_packet[TestMessage::getSize()];
    client_socket.receive(serialized_packet, TestMessage::getSize());
    TestMessage packet = TestMessage::deserialize(serialized_packet);
    packet.print();
}


int main() {
    cout << "**SOCKET MANAGER TEST**" << endl;

    thread server_thread(server);
    thread client_thread(client);

    server_thread.join();
    client_thread.join();

    return 0;
}
