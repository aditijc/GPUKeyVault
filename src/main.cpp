#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <streambuf>
#include "ecdh.h"
#include "interface.h"

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
        std::cout << "Not implemented" << std::endl;
        return 1;
    }
    else if (args.at(1) != "-c") {
        std::cout << "Second argument must indicate CPU or GPU usage [-c|-g]." << std::endl;
        return 1;
    }

    // Check that third argument is valid 
    if (args.at(2) != "-e" && args.at(2) != "-d" && args.at(2) != "-n") {
        std::cout << "Third argument must indicate encrypting, decrypting, or generating new keys [-e|-d|-n]."  << std::endl;
    }

    int mode = ENCRYPT;
    if (args.at(2) == "-d") {
        mode = DECRYPT;
    } else if (args.at(2) == "-n") {
        mode = NEW;
    }

    // If we are encrypting or decrypting, check that the next argument is a valid file. 
    const char *pub_file;
    const char *priv_file;
    const char *message;
    if (mode == ENCRYPT || mode == DECRYPT) {
        std::ifstream file(args.at(3));
        if (!file) {
            std::cout << "Fourth argument must be valid file path when encrypting and decrypting." << std::endl;
            return 1;
        }
        std::string str((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
        if (mode == ENCRYPT) {
            std::cout << "Encrypting: " << str << std::endl;
        } else {
            std::cout << "Decrypting: " << str << std::endl;
        }
        message = str.c_str();
        // TODO: Handle invalid files here
        pub_file = args.at(4).c_str();
        priv_file = args.at(5).c_str();
    } else {
        // We are creating a new public private key pair, so we do not need to specify a message file.
        pub_file = args.at(3).c_str();
        priv_file = args.at(4).c_str();
    }

    // Call functions based on pspecified parameters
    if (CPU == true) {
        if (args.front() == "ecdh") {
            if (mode == NEW) {
                generate_ecdh_key_pair(pub_file, priv_file);
            }
            else if (mode == ENCRYPT) {
                char * encrypted = encrypt_ecdh(pub_file, priv_file, message);
                std::cout << encrypted << std::endl;
            } 
            else {
                decrypt_ecdh(pub_file, priv_file, message);
            }
        }
    }

    return 0;
}