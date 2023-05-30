#include <iostream>
#include <cassert>
#include <string>
#include "ecdh.h"
#include "aes.h"
#include "rsa.h"

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

void test_rsa() {
    rsa_keygen();
    // Load keys from PEM files
    RSA* privateKey = loadKeyFromPem("private-keys/rsa_private_demo.pem", true);
    RSA* publicKey = loadKeyFromPem("public-keys/rsa_public_demo.pem", false);

    std::string plaintext = "Hello, RSA!";
    std::string encrypted = rsa_encrypt(publicKey, plaintext);
    std::string decrypted = rsa_decrypt(privateKey, encrypted);

    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Encrypted: " << encrypted << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;

    RSA_free(privateKey);
    RSA_free(publicKey);
}

void test_rsa_aes() {
    std::string plainText = "Hello, World!";
    std::string key = generate_aes_key(); // AES-256 key

    std::string encryptedText = aes_default_encrypt(plainText, key);

    std::cout << "Plain Text: " << plainText << std::endl;
    std::cout << "Encrypted Text: " << encryptedText << std::endl;

    std::string decryptedText = aes_default_decrypt(encryptedText, key);

    std::cout << "Decrypted Text: " << decryptedText << std::endl;
}

int main() {
    std::cout << "Testing ECDH Encryption and Decryption" << std::endl;
    test_ecdh();
    std::cout << "\nTesting RSA Encryption and Decryption" << std::endl;
    test_rsa();
    std::cout << "\nTesting Default AES Encryption and Decryption" << std::endl;
    test_rsa_aes();
    return 0;
}