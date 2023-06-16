#include "interface.h"

using namespace std;

void display_encryption_modes() {
    for (auto i: algs) {
            cout << i << ' ';
        }
    cout << endl;
}

void display_help() {
    cout << "GPUKeyGen provides encryption and decryption algorithms and public/private key generation and storage." << endl;
    cout << "CPU USAGE: [encryption mode] [-c] [-e FILE|-d FILE|-n] [PUB-KEY] [PRIV-KEY]" << endl;
    cout << "GPU USAGE: [encryption mode] [-g] [FILE]" << endl << endl;
    cout << "ENCRYPTION MODES: ";
    display_encryption_modes();
    cout << endl;
    cout << "OPTIONS:" << endl;
    cout << "  -h: display the help menu." << endl;
    cout << "  -l: list all available public/private key pairs." << endl;
    cout << "  -c: CPU mode." << endl;
    cout << "  -g: GPU mode." << endl;
    cout << "  -e: Encrypt. Proceeding argument is assumed to be file path containing text to encrypt." << endl;
    cout << "  -d: Decrypt. Proceeding argument is assumed to be file path containing text to decrypt." << endl;   
    cout << "  -n: Generate a new public/private key pair." << endl << endl;  
    cout << "[PUB-KEY]: a pem file containing a public key. Assumed to be located in public-keys directory." << endl;
    cout << "[PRIV-KEY]: a pem file containing a private key. Assumed to be located in private-keys directory." << endl;
}