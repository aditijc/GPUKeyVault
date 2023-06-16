#include <iostream>
#include <cassert>
#include <string>
#include "ecdh.h"
#include "aes.h"
#include "rsa.h"

using namespace std;

void test_ecdh() {
    const char *pub_file = "public-keys/ecdh_public_demo.pem";
    const char *priv_file = "private-keys/ecdh_private_demo.pem";
    const char *message = "hello world";
    cout << "Message: " << message << endl;
    generate_ecdh_key_pair(pub_file, priv_file);
    cout << "ECDH keys successfully generated" << endl;
    char *encrypted = encrypt_ecdh(pub_file, priv_file, message);
    cout << "Message successfully encrypted" << endl;
    char *decrypted = decrypt_ecdh(pub_file, priv_file, encrypted);
    cout << "Decrypted: " << decrypted << endl;

    string m_str = message;
    string d_str = decrypted;
    assert(m_str == d_str);
    cout << "Message decrypted correctly" << endl;
}

void test_rsa() {
    rsa_keygen("private-keys/rsa_private_demo.pem", "public-keys/rsa_public_demo.pem");
    const string pub_file = "public-keys/rsa_public_demo.pem";
    const string priv_file = "private-keys/rsa_private_demo.pem";
    string plaintext = "Hello, RSA!";
    string encrypted = rsa_encrypt(pub_file, plaintext);
    string decrypted = rsa_decrypt(priv_file, encrypted);
    cout << "Plaintext: " << plaintext << endl;
    cout << "Encrypted: " << encrypted << endl;
    cout << "Decrypted: " << decrypted << endl;
    assert(plaintext.compare(decrypted.c_str()) == 0);
}

void test_rsa_aes() {
    string plainText = "Hello, World!";
    string key = generate_aes_key(); // AES-256 key

    string encryptedText = aes_default_encrypt(plainText, key);

    cout << "Plain Text: " << plainText << endl;
    cout << "Encrypted Text: " << encryptedText << endl;

    string decryptedText = aes_default_decrypt(encryptedText, key);

    cout << "Decrypted Text: " << decryptedText << endl;
    assert(plainText.compare(decryptedText.c_str()) == 0);
}

void test_rsa_pgp() {
    const string pub_file = "public-keys/rsa_public.pem";
    const string priv_file = "private-keys/rsa_private.pem";
    string message = "Hello RSA-PGP!";
    cout << "Message: " << message << endl;
    rsa_keygen(priv_file, pub_file);
    string aes_key = generate_aes_key();
    string encrypted_message = aes_default_encrypt(message, aes_key);
    string aes_encrypted_key = rsa_encrypt(pub_file, aes_key);
    cout << "Encrypted Message: " << encrypted_message << endl;
    string aes_decrypted_key = rsa_decrypt(priv_file, aes_encrypted_key);
    string decrypted_message = aes_default_decrypt(encrypted_message, aes_decrypted_key);
    cout << "Decrypted Message: " << decrypted_message.c_str() << endl;
    assert(message.compare(decrypted_message.c_str()) == 0);
}

int main() {
    cout << "Testing RSA Encryption and Decryption" << endl;
    test_rsa();
    cout << "\nTesting Default AES Encryption and Decryption" << endl;
    test_rsa_aes();
    cout << "\nTesting PGP Encryption and Decryption with RSA" << endl;
    test_rsa_pgp();
    cout << "\nTesting PGP Encryption and Decryption with ECDH" << endl;
    test_ecdh();
    return 0;
}