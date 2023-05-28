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
#include "ecdh.h"
#include "aes.h"

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

unsigned char *get_shared_secret(const char *priv_file, const char *pub_file) {
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

char *encrypt_ecdh(const char *pub_file, const char *priv_file, const char *message) {
    unsigned char *shared_secret = get_shared_secret(priv_file, pub_file);
    size_t shared_secret_len = sizeof(shared_secret);
    return aes_encrypt(shared_secret, shared_secret_len, message);
}

char *decrypt_ecdh(const char *pub_file, const char *priv_file, const char *encrypted_message) {
    unsigned char* shared_secret = get_shared_secret(priv_file, pub_file);
    return aes_decrypt(shared_secret, encrypted_message);    
}
