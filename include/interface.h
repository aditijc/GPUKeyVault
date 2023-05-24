#include <string>
#include <vector>
#include <iostream>

const std::vector<std::string> algs = {"ecdh"};

enum operations {
    ENCRYPT = 0,
    DECRYPT = 1,
    NEW = 2
};

void display_encryption_modes();

void display_help();