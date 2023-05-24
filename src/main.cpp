#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include "ecdh.h"

const std::vector<std::string> algs = {"ecdh"};

void display_encryption_modes() {
    for (auto i: algs) {
            std::cout << i << ' ';
        }
    std::cout << std::endl;
}

void display_help() {
    std::cout << "GPUKeyGen provides encryption and decryption algorithms and public/private key generation and storage." << std::endl;
    std::cout << "USAGE: [encryption mode] [-c|-g] [-e FILE|-d FILE|-n] [-pub PUB-KEY] [-priv PRIV-KEY]" << std::endl << std::endl;
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
    std::cout << "  -n: Generate a new public/private key pair." << std::endl;
    std::cout << "  -pub: Public key to be used. Must be specified when encrypting or decrypting." << std::endl;
    std::cout << "  -priv: Private key to be used. Must be specified when encrypting or decrypting." << std::endl;    
}

int main(int argc, char *argv[]) {
    std::vector<std::string> args;
    if (argc == 1) {
        display_help();
        return 0;
    }

    // Transform char* argv[] into vector<string>
    for (int i = 1; i < argc; i++) {
        args.emplace_back(argv[i]);
    }

    // -h and -l take priority as arguments since they don't perform operations
    if (std::find(args.begin(), args.end(), "-h") != args.end()) {
        display_help();
        return 0;
    }

    if (std::find(args.begin(), args.end(), "-l") != args.end()) {
        std::cout << "not available yet" << std::endl;
        return 0;
    }

    // check that first argument is valid encryption mode
    if (std::find(algs.begin(), algs.end(), args.front()) == algs.end()) {
        std::cout << "First argument must be valid encryption mode: ";
        display_encryption_modes();
        return 1;
    }

    // Check if using CPU or GPU
    bool CPU = true;
    if (args.at(1) == "-g") {
        CPU = false;
        std::cout << "Not implemented";
        return 1;
    }
    else if (args.at(1) != "-c") {
        std::cout << "Second argument must indicate CPU or GPU usage [-c|-g].";
        return 1;
    }

    // Check that third argument is valid 
    if (args.at(2) != "-e" || args.at(2) != "-d" || args.at(2) != "-n") {
        std::cout << "Third argument must indicate encrypting, decrypting, or generating new keys [-e|-d|-n].";        
    }

    


    return 0;
}