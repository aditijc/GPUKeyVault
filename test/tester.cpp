#include <iostream>
#include <cassert>
#include <string>
#include "ecdh.h"

void test_ecdh() {
    const char *pub_file = "public-keys/ecdh_public_demo.pem";
    const char *priv_file = "private-keys/ecdh_private_demo.pem";
    const char *message = "hello world";

    std::cout << "Message: " << message << std::endl;
    generate_ecdh_key_pair(pub_file, priv_file);
    std::cout << "ECDH keys successfully generated" << std::endl;
    char *encrypted = encrypt_ecdh(pub_file, priv_file, message);
    std::cout << "Message successfully encrypted" << std::endl;
    char *decrypted = decrypt_ecdh(pub_file, priv_file, encrypted);
    std::cout << "Decrypted: " << decrypted << std::endl;

    std::string m_str = message;
    std::string d_str = decrypted;
    assert(m_str == d_str);
    std::cout << "Message decrypted correctly" << std::endl;
}

int main() {
    test_ecdh();
    return 0;
}