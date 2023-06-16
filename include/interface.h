#include <string>
#include <vector>
#include <iostream>

const std::vector<std::string> algs = {"ecdh", "rsa"};
const std::string PUB_DIR = "public-keys/";
const std::string PRIV_DIR = "private-keys/";
const int MAX_DIR_LEN = 1000;

enum operations {
    ENCRYPT = 0,
    DECRYPT = 1,
    NEW = 2
};

void display_encryption_modes();

void display_help();