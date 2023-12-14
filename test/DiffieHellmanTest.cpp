#include <cassert>
#include <openssl/dh.h>
#include "../src/crypto/DiffieHellman.h"
#include "iostream"

using namespace std;

void testGenerateLowLevelStructure() {
    DH * dh = DiffieHellman().generateLowLevelStructure();
    assert(dh != nullptr);
    cout << "testGenerateLowLevelStructure() passed" << endl;
}

int main() {
    testGenerateLowLevelStructure();
    return 0;
}
