#include <iostream>
#include <string>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <vector>


using namespace std;


int main() {
    cout<< "*********************\n"
           "***** KEYS TEST *****\n"
           "*********************\n" << endl;

    //Long term key and password variables
    EVP_PKEY* long_term_key;
    string password;

    //List of certificate names
    std::vector<std::string> encrypted_keys_name_list = {"Francesco", "Luca", "Salvatore"};

    // Iterate through the list
    for (const std::string& name : encrypted_keys_name_list) { //iterate the list storing in a constant string "name"
        cout << "**Test password on encrypted key for " << name << "**" << endl;

        // Construct the encrypted private key filename
        string private_key_file = "../resources/encrpyted_private_keys/" + name + "_key.pem";

        // Prompt user to enter a password for the current key
        cout << "Insert password for " << name << " : ";
        cin >> password;

        // Open the encrypted private key file
        BIO *bio = BIO_new_file(private_key_file.c_str(), "r");
        if (!bio) {
            // Handle error if the key file cannot be opened
            cerr << "KeyTest - No long term key associated to the username" << endl;
            return -1;
        }

        // Read the encrypted private key using the provided password
        long_term_key = PEM_read_bio_PrivateKey(bio, 0, 0, (void *) password.c_str());
        BIO_free(bio);

        // Check if the password is correct
        if (!long_term_key) {
            cerr << "KeyTest - Wrong password" << endl;
            return -1;
        }
    }

    cout << "+TEST PASSED+" << endl;
    return 0;

}
