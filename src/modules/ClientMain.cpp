#include <iostream>
#include <csignal>

#include "Client.h"

using namespace std;

void handleSignal(int signal_code) {
    switch (signal_code) {

        case SIGINT:
            cout << "\nExit" << endl;
            throw -3;

        case SIGPIPE:
            throw -4;

        default:
            break;
    }
}

int main() {

    // register the signal handler for SIGINT and SIGPIPE
    signal(SIGINT, handleSignal);
    signal(SIGPIPE, handleSignal);

    while (true) {
        if (Client().run() == 1)
            break;
    }

    return 0;

}