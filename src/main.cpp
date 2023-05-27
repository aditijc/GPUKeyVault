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

    operations mode = ENCRYPT;
    if (args.at(2) == "d") {
        mode = DECRYPT;
    } else {
        mode = NEW;
    }

    // If we are encrypting or decrypting, check that the next argument is a valid file. 
    if (mode == ENCRYPT || mode == DECRYPT) {
        std::ifstream file(args.at(3));
        std::string str((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    }


    return 0;
}