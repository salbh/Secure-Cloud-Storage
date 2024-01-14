#include <iostream>
#include <thread>
#include <mutex>
#include <arpa/inet.h>
#include <condition_variable>
#include <cstring>
#include <iomanip>
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
void sendTextMessage(SocketManager &socket) {
    auto *msg = (uint8_t *) MSG;
    for (int i = 0; i < MSG_NUM; ++i) {
        {
            lock_guard<mutex> lock(g_mutex);
            cout << "SocketManagerTest - Client - Send message: " << msg << endl;
            socket.send(msg, TEST_MSG_SIZE);
        }
    }
    cout << endl;
}

/**
 * Function to receive a text message (executed by the Server)
 * @param socket The socket used to receive the text message
 */
void receiveTextMessage(SocketManager &socket) {
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
void sendGenericMessage(SocketManager &socket) {
    // Determine the size of the plaintext and ciphertext
    size_t text_len = SimpleMessage::getSize();
    // Create a SimpleMessage with NACK code
    SimpleMessage simple_message(static_cast<uint8_t>(Result::ACK));
    // Serialize the SimpleMessage to obtain a byte buffer
    uint8_t *serialized_message = simple_message.serialize();
    {
        lock_guard<mutex> lock(g_mutex);
        // Print the plaintext obtained from serialization
        cout << "SocketManagerTest - Server - Serialized plaintext: " << endl;
        for (int i = 0; i < text_len; i++) {
            cout << hex << setw(2) << setfill('0') << static_cast<int>(serialized_message[i]);
        }
        cout << dec << endl << endl;
    }
    // Create a Generic message with counter set to 1
    Generic generic_message(1);
    // Encrypt the serialized SimpleMessage using a key
    const unsigned char key[] = "1234567890123456";
    generic_message.encrypt(key, serialized_message, static_cast<int>(text_len));
    // Serialize the Generic message, which now contains the encrypted SimpleMessage
    serialized_message = generic_message.serialize();
    {
        lock_guard<mutex> lock(g_mutex);
        cout << "SocketManagerTest - Server - Generic message (to send): " << endl;
        generic_message.print(text_len);
    }
    // Send the serialized Generic message over the socket
    if (socket.send(serialized_message,
                    Generic::getSize(text_len)) == -1) {
        lock_guard<mutex> lock(g_mutex);
        cout << "SocketManagerTest - Server - Error in sending Generic message\n" << endl;
    }
    // Free the allocated memory for the serialized message buffer
    delete[] serialized_message;
}

/**
 * Function to receive a Generic message (executed by the Client)
 * @param socket The socket used to receive the Generic message
 */
void receiveGenericMessage(SocketManager &socket) {
    // Determine the size of the plaintext and ciphertext
    size_t text_len = SimpleMessage::getSize();
    // Determine the expected size of the Generic message buffer
    size_t generic_message_size = Generic::getSize(text_len);
    // Allocate memory for the buffer to receive the Generic message
    auto *serialized_message = new uint8_t[generic_message_size];
    // Receive the Generic message from the server
    if (socket.receive(serialized_message, generic_message_size) == -1) {
        lock_guard<mutex> lock(g_mutex);
        cout << "SocketManagerTest - Client - Error in receiving Generic message\n" << endl;
    }
    // Deserialize the received Generic message
    Generic generic_message = Generic::deserialize(serialized_message, text_len);
    {
        lock_guard<mutex> lock(g_mutex);
        cout << "SocketManagerTest - Client - Generic message (received): " << endl;
        generic_message.print(text_len);
    }
    // Free the allocated memory for the received message buffer
    delete[] serialized_message;
    // Allocate memory for the plaintext buffer
    auto *plaintext = new uint8_t[text_len];
    // Decrypt the Generic message to obtain the serialized SimpleMessage
    const unsigned char key[] = "1234567890123456";
    generic_message.decrypt(key, plaintext);
    // Create a SimpleMessage object by deserializing the decrypted data
    SimpleMessage simple_message = SimpleMessage::deserialize(plaintext);
    {
        lock_guard<mutex> lock(g_mutex);
        // Print the plaintext obtained from decryption
        cout << "SocketManagerTest - Client - Decrypted plaintext: " << endl;
        for (int i = 0; i < text_len; i++) {
            cout << hex << setw(2) << setfill('0') << static_cast<int>(plaintext[i]);
        }
        cout << dec << endl << endl;
        // Output the message code of the received SimpleMessage
        cout << "SocketManagerTest - Client - Received message code: " <<
             (int) simple_message.getMessageCode() << endl;
    }
    // Free the allocated memory for the plaintext buffer
    delete[] plaintext;
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
        // Receive a text message for test
        receiveTextMessage(server_comm_socket);
        // Send a Generic message
        sendGenericMessage(server_comm_socket);
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
    // Init client socket
    SocketManager client_socket("localhost", 5000);
    // Send a text message for test
    sendTextMessage(client_socket);
    // Receive a Generic message
    receiveGenericMessage(client_socket);
    {
        unique_lock<mutex> lock(g_mutex);
        // Wait for the server to complete the test
        g_cv.wait(lock, [] { return g_testCompleted; });
    }
}

int main() {
    cout << "*******************************\n"
            "***** SOCKET MANAGER TEST *****\n"
            "*******************************\n" << endl;
    thread server_thread(server);
    thread client_thread(client);

    server_thread.join();
    client_thread.join();

    cout << "\n+TEST PASSED+" << endl;
    return 0;
}
