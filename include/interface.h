#include <string>
#include <vector>
#include <iostream>

const std::vector<std::string> algs = {"ecdh"};
const std::string PUB_DIR = "public-keys/";
const std::string PRIV_DIR = "private-keys/";

enum operations {
    ENCRYPT = 0,
    DECRYPT = 1,
    NEW = 2
};

void display_encryption_modes();

void display_help();