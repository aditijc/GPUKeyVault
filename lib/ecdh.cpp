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

unsigned char* get_shared_secret(const char *priv_file, const char *pub_file) {
    FILE *file = fopen(priv_file, "r");
    EC_KEY *ec_privkey = PEM_read_ECPrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    FILE *f = fopen(pub_file, "r");
    EC_KEY *ec_pubkey = PEM_read_EC_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);

    if (!ec_pubkey || !ec_privkey) {
        std::cerr << "Encryption Error: Failed to read EC public or private keys." << std::endl;
        return nullptr;
    }
    // Create EVP_PKEY objects from EC_KEY objects
    EVP_PKEY* evp_privkey = EVP_PKEY_new();
    EVP_PKEY* evp_pubkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(evp_privkey, ec_privkey) || !EVP_PKEY_assign_EC_KEY(evp_pubkey, ec_pubkey)) {
        // Handle error
        std::cout << "Encryption Error: EC keys don't exist" << std::endl;
        EVP_PKEY_free(evp_privkey);
        EVP_PKEY_free(evp_pubkey);
        return nullptr;
    }
    
    const EC_GROUP *ec_pubgroup = EC_KEY_get0_group(ec_pubkey);
    size_t pubkey_len = EC_GROUP_get_degree(ec_pubgroup) / 8;
    const EC_GROUP *ec_privgroup = EC_KEY_get0_group(ec_privkey);
    size_t privkey_len = EC_GROUP_get_degree(ec_privgroup) / 8;

    if (!ec_pubkey) {
        std::cerr << "Encryption Error: Failed to read EC public key." << std::endl;
        return nullptr;
    }

    // Create ECDH context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(evp_privkey, NULL);
    if (!ctx) {
        // Handle error
        EVP_PKEY_free(evp_privkey);
        EVP_PKEY_free(evp_pubkey);
        EC_KEY_free(ec_privkey);
        EC_KEY_free(ec_pubkey);
        return nullptr;
    }

    // Initialize the context for ECDH key derivation
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        // Handle error
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_privkey);
        EVP_PKEY_free(evp_pubkey);
        EC_KEY_free(ec_privkey);
        EC_KEY_free(ec_pubkey);
        return nullptr;
    }

    // Provide the peer's public key to the context
    if (EVP_PKEY_derive_set_peer(ctx, evp_pubkey) <= 0) {
        // Handle error
        EVP_PKEY_CTX_free(ctx);
        EC_KEY_free(ec_privkey);
        EC_KEY_free(ec_pubkey);
        return nullptr;
    }

    // Determine the size of the shared secret
    size_t shared_secret_len;
    if (EVP_PKEY_derive(ctx, NULL, &shared_secret_len) <= 0) {
        // Handle error
        EVP_PKEY_CTX_free(ctx);
        EC_KEY_free(ec_privkey);
        EC_KEY_free(ec_pubkey);
        return nullptr;
    }
    // Allocate memory for the shared secret
    unsigned char* shared_secret = new unsigned char[shared_secret_len];

    // Derive the shared secret
    if (EVP_PKEY_derive(ctx, shared_secret, &shared_secret_len) <= 0) {
        // Handle error
        delete[] shared_secret;
        EVP_PKEY_CTX_free(ctx);
        EC_KEY_free(ec_privkey);
        EC_KEY_free(ec_pubkey);
        return nullptr;
    }

    // Clean up memory
    EVP_PKEY_CTX_free(ctx);
    EC_KEY_free(ec_privkey);
    EC_KEY_free(ec_pubkey);
    return shared_secret;
}

char *aes_encrypt(unsigned char *shared_secret, size_t shared_secret_len, const char *message) {
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int block_size = EVP_CIPHER_block_size(cipher);

    EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
    if (!aes_ctx) {
        std::cerr << "Encryption Error: Failed to create encryption context." << std::endl;
        // EC_KEY_free(ec_pubkey);
        delete[] shared_secret;
        return nullptr;
    }

    unsigned char iv[block_size];
    memset(iv, 0, sizeof(iv));

    unsigned char *ciphertext = new unsigned char[shared_secret_len + block_size];
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(aes_ctx, cipher, NULL, shared_secret, iv) != 1 ||
        EVP_EncryptUpdate(aes_ctx, ciphertext, &ciphertext_len, reinterpret_cast<const unsigned char *>(message),
                        strlen(message)) != 1 ||
        EVP_EncryptFinal_ex(aes_ctx, ciphertext + ciphertext_len, &ciphertext_len) != 1) {
        std::cerr << "Encryption failed." << std::endl;
        // EC_KEY_free(ec_key);
        delete[] shared_secret;
        delete[] ciphertext;
        EVP_CIPHER_CTX_free(aes_ctx);
        return nullptr;
    }

    EVP_CIPHER_CTX_free(aes_ctx);
    delete[] shared_secret;
    return reinterpret_cast<char *>(ciphertext);
}

char *aes_decrypt(unsigned char *shared_secret, const char *encrypted_message) {
    // Perform symmetric decryption using the shared secret
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int block_size = EVP_CIPHER_block_size(cipher);

    EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
    if (!aes_ctx) {
        std::cerr << "Failed to create decryption context." << std::endl;
        delete[] shared_secret;
        return nullptr;
    }

    unsigned char iv[block_size];
    memset(iv, 0, sizeof(iv));

    unsigned char *plaintext = new unsigned char[strlen(encrypted_message) + block_size];
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(aes_ctx, cipher, NULL, shared_secret, iv) != 1 ||
        EVP_DecryptUpdate(aes_ctx, plaintext, &plaintext_len, reinterpret_cast<const unsigned char *>(encrypted_message),
                          strlen(encrypted_message)) != 1 ||
        EVP_DecryptFinal_ex(aes_ctx, plaintext + plaintext_len, &plaintext_len) != 1) {
        std::cerr << "Decryption failed." << std::endl;
        delete[] shared_secret;
        delete[] plaintext;
        EVP_CIPHER_CTX_free(aes_ctx);
        return nullptr;
    }

    EVP_CIPHER_CTX_free(aes_ctx);
    delete[] shared_secret;
    return reinterpret_cast<char *>(plaintext);
}

char *encrypt_ecdh(const char *pub_file, const char *priv_file, const char *message) {
    unsigned char *shared_secret = get_shared_secret(priv_file, pub_file);
    size_t shared_secret_len = sizeof(shared_secret);
    return aes_encrypt(shared_secret, shared_secret_len, message);
}

char *decrypt_ecdh(const char *pub_file, const char *priv_file, const char *encrypted_message) {
    unsigned char* shared_secret = get_shared_secret(priv_file, pub_file);
    return aes_decrypt(shared_secret, encrypted_message);    
}

int main() {
    const char *priv_file = "private_key.pem";
    const char *pub_file = "public_key.pem";
    const char *priv_file2 = "private_key2.pem";
    const char *pub_file2 = "public_key2.pem";
    generate_ecdh_key_pair(pub_file, priv_file);
    generate_ecdh_key_pair(pub_file2, priv_file2);
    const char *message = "Hello, ECDH!";
    std::cout << "Original message: " << message << std::endl;

    char *encrypted_message = encrypt_ecdh(pub_file2, priv_file, message);
    if (encrypted_message) {
        std::cout << "Encrypted message: " << encrypted_message << std::endl;

        char *decrypted_message = decrypt_ecdh(pub_file, priv_file2, encrypted_message);
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