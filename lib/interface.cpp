#include "interface.h"

void display_encryption_modes() {
    for (auto i: algs) {
            std::cout << i << ' ';
        }
    std::cout << std::endl;
}

void display_help() {
    std::cout << "GPUKeyGen provides encryption and decryption algorithms and public/private key generation and storage." << std::endl;
    std::cout << "USAGE: [encryption mode] [-c|-g] [-e FILE|-d FILE|-n] [PUB-KEY] [PRIV-KEY]" << std::endl << std::endl;
    std::cout << "ENCRYPTION MODES: ";
    display_encryption_modes();
    std::cout << std::endl;
    std::cout << "OPTIONS:" << std::endl;
    std::cout << "  -h: display the help menu." << std::endl;
    std::cout << "  -l: list all available public/private key pairs." << std::endl;
    std::cout << "  -c: CPU mode." << std::endl;
    std::cout << "  -g: GPU mode." << std::endl;
    std::cout << "  -e: Encrypt. Proceeding argument is assumed to be file path containing text to encrypt." << std::endl;
    std::cout << "  -d: Decrypt. Proceeding argument is assumed to be file path containing text to decrypt." << std::endl;   
    std::cout << "  -n: Generate a new public/private key pair." << std::endl << std::endl;  
    std::cout << "[PUB-KEY]: a pem file containing a public key. Assumed to be located in public-keys directory." << std::endl;
    std::cout << "[PRIV-KEY]: a pem file containing a private key. Assumed to be located in private-keys directory." << std::endl;
}