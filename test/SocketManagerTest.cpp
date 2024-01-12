#include <iostream>
#include <chrono>
#include <thread>
#include <mutex>
#include <arpa/inet.h>
#include <condition_variable>
#include <cstring>
#include <csignal>
#include "SocketManager.h"
#include "Generic.h"
#include "SimpleMessage.h"
#include "CodesManager.h"

#define MSG "hello\0"
#define TEST_MSG_SIZE 6
#define MSG_NUM 3

using namespace std;

// Global mutex for synchronization
mutex g_mutex;
condition_variable g_cv;
bool g_testCompleted = false;

/**
 * Function to send a text message (executed by the Client)
 * @param socket The socket used to send the text message
 */
void sendTextMessage(SocketManager& socket) {
    uint8_t *msg = (uint8_t *) MSG;

    for (int i = 0; i < MSG_NUM; ++i) {
        {
            lock_guard<mutex> lock(g_mutex);
            cout << "SocketManagerTest - Client - Send message: " << msg << endl;
            socket.send(msg, TEST_MSG_SIZE);
        }
        this_thread::sleep_for(chrono::milliseconds(50)); // Introduce delay for synchronization
    }
    cout << endl;
}

/**
 * Function to receive a text message (executed by the Server)
 * @param socket The socket used to receive the text message
 */
void receiveTextMessage(SocketManager& socket) {
    for (int i = 0; i < MSG_NUM; ++i) {
        uint8_t msg[TEST_MSG_SIZE];

        socket.receive(msg, TEST_MSG_SIZE);
        {
            lock_guard<mutex> lock(g_mutex);
            cout << "SocketManagerTest - Server - Test Message Received: " << msg << endl;

            if (!strcmp((const char *) msg, MSG))
                cout << "SocketManagerTest - Server - Test Message Match\n" << endl;
        }
    }
}

/**
 * Function to send a Generic message with an ACK (executed by the Server)
 * @param socket The socket used to send the Generic message
 */
void sendGenericMessage(SocketManager& socket) {
    SimpleMessage simple_message(static_cast<uint8_t>(Result::ACK));
    uint8_t *serialized_message = simple_message.serialize();
    Generic generic_message(1);
    const unsigned char key[] = "1234567890123456";

    generic_message.encrypt(key, serialized_message, sizeof(uint8_t));
    serialized_message = generic_message.serialize();
    if (socket.send(serialized_message, Generic::getSize(sizeof(uint8_t))) == -1) {
        lock_guard<mutex> lock(g_mutex);
        cout << "SocketManagerTest - Server - Error in sending Generic message\n" << endl;
    }
    delete[] serialized_message;
}

/**
 * Function to receive a Generic message (executed by the Client)
 * @param socket The socket used to receive the Generic message
 */
void receiveGenericMessage(SocketManager& socket) {
    size_t generic_message_size = Generic::getSize(sizeof(uint8_t));
    uint8_t *serialized_message = new uint8_t[generic_message_size];
    if (socket.receive(serialized_message, generic_message_size) == -1) {
        lock_guard<mutex> lock(g_mutex);
        cout << "SocketManagerTest - Client - Error in receiving Generic message\n" << endl;
    }
    Generic generic_message = Generic::deserialize(serialized_message, generic_message_size);
    delete[] serialized_message;
    uint8_t *plaintext = new uint8_t[generic_message_size];
    const unsigned char key[] = "1234567890123456";
    generic_message.decrypt(key, plaintext);
    SimpleMessage simple_message;
    simple_message.deserialize(plaintext);
    {
        lock_guard<mutex> lock(g_mutex);
        cout << simple_message.getMessageCode();
    }
}

void server() {
    {
        lock_guard<mutex> lock(g_mutex);
        cout << "*SERVER SIDE RUN*\n" << endl;
    }

    // Init Server listening socket
    SocketManager server_socket("localhost", 5000, 10);
    int server_socket_descriptor = server_socket.accept();
    if (server_socket_descriptor == -1) {
        lock_guard<mutex> lock(g_mutex);
        cout << "SocketManagerTest - Error on accept function" << endl;
    } else {
        // Init Server communication socket
        SocketManager server_comm_socket(server_socket_descriptor);
        this_thread::sleep_for(chrono::seconds(2));
        // Receive a text message for test
        receiveTextMessage(server_comm_socket);
        // Send a Generic message
        sendGenericMessage(server_comm_socket);
        this_thread::sleep_for(chrono::seconds(3));
    }

    {
        lock_guard<mutex> lock(g_mutex);
        g_testCompleted = true;
        g_cv.notify_all(); // Notify waiting threads that the test is completed
    }
}

void client() {
    {
        lock_guard<mutex> lock(g_mutex);
        cout << "*CLIENT SIDE RUN*" << endl;
    }

    this_thread::sleep_for(chrono::seconds(1));

    // Init client socket
    SocketManager client_socket("localhost", 5000);
    // Send a text message for test
    sendTextMessage(client_socket);
    this_thread::sleep_for(chrono::seconds(3));
    // Receive a Generic message
    receiveGenericMessage(client_socket);

    {
        unique_lock<mutex> lock(g_mutex);
        // Wait for the server to complete the test
        g_cv.wait(lock, [] { return g_testCompleted; });
    }
}

int main() {
    {
        lock_guard<mutex> lock(g_mutex);
        cout << "*******************************\n"
                "***** SOCKET MANAGER TEST *****\n"
                "*******************************\n" << endl;
    }

    thread server_thread(server);
    thread client_thread(client);

    server_thread.join();
    client_thread.join();

    {
        lock_guard<mutex> lock(g_mutex);
        cout << "\n+TEST PASSED+" << endl;
    }

    return 0;
}
