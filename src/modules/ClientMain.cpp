#include <iostream>
#include <csignal>

#include "Client.h"

using namespace std;


/**
 * @brief Signal handler for the client.
 * @param signal The signal received by the client.
 * @details Handles signals like SIGINT and SIGPIPE. Exits the program on SIGINT and throws an exception on SIGPIPE.
 */
void clientSignalHandler(int signal) {
    if (signal == SIGINT) {
        cout << "Server closed!" << endl;
        exit(EXIT_SUCCESS);
    } else if (signal == SIGPIPE) {
        cout << "Server: SIGPIPE signal caught!" << endl;
        throw -3;
    }
}

int main() {

    // register the signal handler for SIGINT and SIGPIPE
    signal(SIGINT, clientSignalHandler);
    signal(SIGPIPE, clientSignalHandler);

    while (true) {
        if (Client().run() == 1)
            break;
    }

    return 0;

}