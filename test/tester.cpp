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
    rsa_keygen("private-keys/rsa_private_demo.pem", "public-keys/rsa_public_demo.pem");
    const std::string pub_file = "public-keys/rsa_public_demo.pem";
    const std::string priv_file = "private-keys/rsa_private_demo.pem";
    std::string plaintext = "Hello, RSA!";
    std::string encrypted = rsa_encrypt(pub_file, plaintext);
    std::string decrypted = rsa_decrypt(priv_file, encrypted);
    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Encrypted: " << encrypted << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;
    assert(plaintext.compare(decrypted.c_str()) == 0);
}

void test_rsa_aes() {
    std::string plainText = "Hello, World!";
    std::string key = generate_aes_key(); // AES-256 key

    std::string encryptedText = aes_default_encrypt(plainText, key);

    std::cout << "Plain Text: " << plainText << std::endl;
    std::cout << "Encrypted Text: " << encryptedText << std::endl;

    std::string decryptedText = aes_default_decrypt(encryptedText, key);

    std::cout << "Decrypted Text: " << decryptedText << std::endl;
    assert(plainText.compare(decryptedText.c_str()) == 0);
}

void test_rsa_pgp() {
    const std::string pub_file = "public-keys/rsa_public.pem";
    const std::string priv_file = "private-keys/rsa_private.pem";
    std::string message = "Hello RSA-PGP!";
    std::cout << "Message: " << message << std::endl;
    rsa_keygen(priv_file, pub_file);
    std::string aes_key = generate_aes_key();
    std::string encrypted_message = aes_default_encrypt(message, aes_key);
    std::string aes_encrypted_key = rsa_encrypt(pub_file, aes_key);
    std::cout << "Encrypted Message: " << encrypted_message << std::endl;
    std::string aes_decrypted_key = rsa_decrypt(priv_file, aes_encrypted_key);
    std::string decrypted_message = aes_default_decrypt(encrypted_message, aes_decrypted_key);
    std::cout << "Decrypted Message: " << decrypted_message.c_str() << std::endl;
    assert(message.compare(decrypted_message.c_str()) == 0);
}

int main() {
    std::cout << "Testing RSA Encryption and Decryption" << std::endl;
    test_rsa();
    std::cout << "\nTesting Default AES Encryption and Decryption" << std::endl;
    test_rsa_aes();
    std::cout << "\nTesting PGP Encryption and Decryption with RSA" << std::endl;
    test_rsa_pgp();
    std::cout << "\nTesting PGP Encryption and Decryption with ECDH" << std::endl;
    test_ecdh();
    return 0;
}