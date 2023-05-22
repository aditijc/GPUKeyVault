#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <iostream>
#include <cassert>
#include <cstring>
#include "../include/ecdh.h"

void generate_ecdh_key_pair(const char *pub_file, const char *priv_file) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    assert(1 == EC_KEY_generate_key(ec_key));
    assert(1 == EC_KEY_check_key(ec_key));

    FILE *f1 = fopen(pub_file, "w");
    PEM_write_EC_PUBKEY(f1, ec_key);
    fclose(f1);

    FILE *f2 = fopen(priv_file, "w");
    PEM_write_ECPrivateKey(f2, ec_key, NULL, NULL, 0, NULL, NULL);
    fclose(f2);

    EC_KEY_free(ec_key);
}

// char *encrypt_ecdh(const char *pub_file, const char *message) {
//     int message_len = sizeof(message);
//     FILE* f = fopen(pub_file, "r");
//     EVP_PKEY* pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
//     fclose(f);

//     // Create/initialize context
//     EVP_PKEY_CTX* ctx;
//     ctx = EVP_PKEY_CTX_new(pkey, NULL);
//     EVP_PKEY_encrypt_init(ctx);

//     // Encryption
//     size_t ciphertextLen;
//     EVP_PKEY_encrypt(ctx, NULL, &ciphertextLen, (const unsigned char *) message, sizeof(message));
//     unsigned char* ciphertext = (unsigned char*)OPENSSL_malloc(ciphertextLen);
//     EVP_PKEY_encrypt(ctx, ciphertext, &ciphertextLen, (const unsigned char*) message, sizeof(message));

//     // Release memory
//     EVP_PKEY_free(pkey);
//     EVP_PKEY_CTX_free(ctx);
//     return (char *) ciphertext;
// }

// char *decrypt_ecdh(char *message, char *private_key) {
//     char *a = (char *) malloc(sizeof(char));
//     return a;
// }

char *encrypt_ecdh(const char *pub_file, const char *message) {
    FILE *f = fopen(pub_file, "r");
    EC_KEY *ec_key = PEM_read_EC_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);

    if (!ec_key) {
        std::cerr << "Failed to read EC public key." << std::endl;
        return nullptr;
    }

    const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
    size_t key_len = EC_GROUP_get_degree(ec_group) / 8;

    // Derive the shared secret using ECDH
    unsigned char *shared_secret = new unsigned char[key_len];
    size_t secret_len = ECDH_compute_key(shared_secret, key_len, EC_KEY_get0_public_key(ec_key), ec_key, NULL);

    if (secret_len == 0) {
        std::cerr << "Failed to compute shared secret (encryption)." << std::endl;
        EC_KEY_free(ec_key);
        delete[] shared_secret;
        return nullptr;
    }

    // Perform symmetric encryption using the shared secret
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int block_size = EVP_CIPHER_block_size(cipher);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create encryption context." << std::endl;
        EC_KEY_free(ec_key);
        delete[] shared_secret;
        return nullptr;
    }

    unsigned char iv[block_size];
    memset(iv, 0, sizeof(iv));

    unsigned char *ciphertext = new unsigned char[key_len + block_size];
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, shared_secret, iv) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, reinterpret_cast<const unsigned char *>(message),
                          strlen(message)) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &ciphertext_len) != 1) {
        std::cerr << "Encryption failed." << std::endl;
        EC_KEY_free(ec_key);
        delete[] shared_secret;
        delete[] ciphertext;
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    EVP_CIPHER_CTX_free(ctx);
    EC_KEY_free(ec_key);
    delete[] shared_secret;

    return reinterpret_cast<char *>(ciphertext);
}

char *decrypt_ecdh(char *message, const char *priv_file) {
    FILE *f = fopen(priv_file, "r");
    EC_KEY *ec_key = PEM_read_ECPrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    if (!ec_key) {
        std::cerr << "Failed to read EC private key." << std::endl;
        return nullptr;
    }

    const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
    size_t key_len = EC_GROUP_get_degree(ec_group) / 8;

    // Derive the shared secret using ECDH
    unsigned char *shared_secret = new unsigned char[key_len];
    size_t secret_len = ECDH_compute_key(shared_secret, key_len, EC_KEY_get0_public_key(ec_key), ec_key, NULL);

    if (secret_len == 0) {
        std::cerr << "Failed to compute shared secret." << std::endl;
        EC_KEY_free(ec_key);
        delete[] shared_secret;
        return nullptr;
    }

    // Perform symmetric decryption using the shared secret
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int block_size = EVP_CIPHER_block_size(cipher);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create decryption context." << std::endl;
        EC_KEY_free(ec_key);
        delete[] shared_secret;
        return nullptr;
    }

    unsigned char iv[block_size];
    memset(iv, 0, sizeof(iv));

    unsigned char *plaintext = new unsigned char[strlen(message) + block_size];
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, shared_secret, iv) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, reinterpret_cast<const unsigned char *>(message),
                          strlen(message)) != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &plaintext_len) != 1) {
        std::cerr << "Decryption failed." << std::endl;
        EC_KEY_free(ec_key);
        delete[] shared_secret;
        delete[] plaintext;
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    EVP_CIPHER_CTX_free(ctx);
    EC_KEY_free(ec_key);
    delete[] shared_secret;

    return reinterpret_cast<char *>(plaintext);
}

int main() {
    const char *priv_file = "private_key.pem";
    const char *pub_file = "public_key.pem";
    generate_ecdh_key_pair(pub_file, priv_file);

    const char *message = "Hello, ECDH!";
    std::cout << "Original message: " << message << std::endl;

    char *encrypted_message = encrypt_ecdh(pub_file, message);
    if (encrypted_message) {
        std::cout << "Encrypted message: " << encrypted_message << std::endl;

        char *decrypted_message = decrypt_ecdh(encrypted_message, priv_file);
        if (decrypted_message) {
            std::cout << "Decrypted message: " << decrypted_message << std::endl;
            delete[] decrypted_message;
        } else {
            std::cerr << "Failed to decrypt the message." << std::endl;
        }

        delete[] encrypted_message;
    } else {
        std::cerr << "Failed to encrypt the message." << std::endl;
    }

    return 0;
}


// int main() {
//     // To Run: g++ lib/ecdsa.cpp -o ecdsa -lssl -lcrypto
//     const char *priv_file = "private_key.pem";
//     const char *pub_file = "public_key.pem";
//     generate_ecdsa_key_pair(pub_file, priv_file);

//     char *sig;
//     unsigned char buff[]= "to be or not to be ,that is the problem.";
//     sign_buff(priv,&buff[0], sizeof(buff), sig);
// }