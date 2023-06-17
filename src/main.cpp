#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <streambuf>
#include <string.h>
#include "ecdh.h"
#include "rsa.h"
#include "cursa.h"
#include "cuaes.h"
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
    }
    else if (args.at(1) != "-c") {
        std::cout << "Second argument must indicate CPU or GPU usage [-c|-g]." << std::endl;
        return 1;
    }
    
    if (CPU == true) {
        // Check that third argument is valid 
        if (args.at(2) != "-e" && args.at(2) != "-d" && args.at(2) != "-n") {
            std::cout << "Third argument must indicate encrypting, decrypting, or generating new keys [-e|-d|-n]." << std::endl;
        }

        int mode = ENCRYPT;
        if (args.at(2) == "-d") {
            mode = DECRYPT;
        } else if (args.at(2) == "-n") {
            mode = NEW;
        }

        // If we are encrypting or decrypting, check that the next argument is a valid file. 
        const char *message;
        char pub_file_mod[MAX_DIR_LEN];
        char priv_file_mod[MAX_DIR_LEN];
        if (mode == ENCRYPT || mode == DECRYPT) {
            std::ifstream file(args.at(3));
            if (!file) {
                std::cout << "Fourth argument must be valid file path when encrypting and decrypting." << std::endl;
                return 1;
            }
            std::string str((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
            message = str.c_str();
            strcpy(pub_file_mod, PUB_DIR.c_str());
            strcat(pub_file_mod, args.at(4).c_str());

            strcpy(priv_file_mod, PRIV_DIR.c_str());
            strcat(priv_file_mod, args.at(5).c_str());

            std::ifstream file1(pub_file_mod);
            if (!file1) {
                std::cout << "Fifth argument must be valid file path when encrypting and decrypting." << std::endl;
                return 1;
            }

            std::ifstream file2(pub_file_mod);
            if (!file2) {
                std::cout << "Sixth argument must be valid file path when encrypting and decrypting." << std::endl;
                return 1;
            }


        } else {
            // We are creating a new public private key pair, so we do not need to specify a message file.
            strcpy(pub_file_mod, PUB_DIR.c_str());
            strcat(pub_file_mod, args.at(3).c_str());

            strcpy(priv_file_mod, PRIV_DIR.c_str());
            strcat(priv_file_mod, args.at(4).c_str());
        }

        // Call functions based on pspecified parameters
        const char *pub_file = pub_file_mod;
        const char *priv_file = priv_file_mod;
        if (args.front() == "ecdh") {
            if (mode == NEW) {
                generate_ecdh_key_pair(pub_file, priv_file);
            }
            else if (mode == ENCRYPT) {
                char *encrypted = encrypt_ecdh(pub_file, priv_file, message);
                std::ofstream out;
                out.open("encrypted");
                out << encrypted;
                out.close();
            } 
            else {
                char *decrypted = decrypt_ecdh(pub_file, priv_file, message);
                std::ofstream out;
                out.open("decrypted");
                out << decrypted;
                out.close();
            }
        }
        else if (args.front() == "rsa") {
            if (mode == NEW) {
                rsa_keygen(priv_file, pub_file);
            }
            else if (mode == ENCRYPT) {
                std::string encrypted = rsa_encrypt(pub_file, message);
                std::ofstream out;
                out.open("encrypted");
                out << encrypted;
                out.close();
            } 
            else {
                std::string decrypted = rsa_decrypt(priv_file, message);
                std::ofstream out;
                out.open("decrypted");
                out << decrypted;
                out.close();
            }
        }
    } 
    // GPU Code
    else { 
        if (args.front() == "rsa") {
            std::string file_path = args.at(2);
            set_rsa_parameters(file_path);
        } else if (args.front() == "aes") {
            std::string file_path = args.at(2);
            set_aes_parameters(file_path);
        } else {
            std::cout << "Invalid encryption form for GPU. RSA and AES available." << std::endl;
            return 1; 
        }
    }

    return 0;
}