#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <iostream>
#include <cassert>
#include <cstring>
#include "dh.h"

void generate_dh_key_pair(const char *pub_file, const char *priv_file) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    EVP_PKEY_CTX_set_dh_nid(ctx, 1);
    EVP_PKEY *pkey = NULL;
    
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        // Error handling
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    FILE *pub_fp = fopen(pub_file, "w");
    if (!pub_fp) {
        // Error handling
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return;
    }
    
    PEM_write_PUBKEY(pub_fp, pkey);
    fclose(pub_fp);

    FILE *priv_fp = fopen(priv_file, "w");
    if (!priv_fp) {
        // Error handling
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return;
    }
    
    PEM_write_PrivateKey(priv_fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(priv_fp);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

char *encrypt_dh(const char *pub_file, const char *priv_file, const char *message) {
    FILE *pub_fp = fopen(pub_file, "r");
    if (!pub_fp) {
        // Error handling
        return NULL;
    }
    
    EVP_PKEY *pub_key = PEM_read_PUBKEY(pub_fp, NULL, NULL, NULL);
    fclose(pub_fp);

    FILE *priv_fp = fopen(priv_file, "r");
    if (!priv_fp) {
        // Error handling
        EVP_PKEY_free(pub_key);
        return NULL;
    }
    
    EVP_PKEY *priv_key = PEM_read_PrivateKey(priv_fp, NULL, NULL, NULL);
    fclose(priv_fp);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        // Error handling
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return NULL;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_encrypt(ctx, NULL, NULL, (const unsigned char *)message, strlen(message)) <= 0) {
        // Error handling
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return NULL;
    }

    size_t encrypted_len;
    if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_len, (const unsigned char *)message, strlen(message)) <= 0) {
        // Error handling
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return NULL;
    }

    unsigned char *encrypted_data = (unsigned char *)malloc(encrypted_len);
    if (!encrypted_data) {
        // Error handling
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return NULL;
    }

    if (EVP_PKEY_encrypt(ctx, encrypted_data, &encrypted_len, (const unsigned char *)message, strlen(message)) <= 0) {
        // Error handling
        free(encrypted_data);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pub_key);
    EVP_PKEY_free(priv_key);
    
    return (char *)encrypted_data;
}

char *decrypt_dh(const char *pub_file, const char *priv_file, const char *encrypted_message) {
    FILE *pub_fp = fopen(pub_file, "r");
    if (!pub_fp) {
        // Error handling
        return NULL;
    }
    
    EVP_PKEY *pub_key = PEM_read_PUBKEY(pub_fp, NULL, NULL, NULL);
    fclose(pub_fp);

    FILE *priv_fp = fopen(priv_file, "r");
    if (!priv_fp) {
        // Error handling
        EVP_PKEY_free(pub_key);
        return NULL;
    }
    
    EVP_PKEY *priv_key = PEM_read_PrivateKey(priv_fp, NULL, NULL, NULL);
    fclose(priv_fp);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        // Error handling
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return NULL;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_decrypt(ctx, NULL, NULL, (const unsigned char *)encrypted_message, strlen(encrypted_message)) <= 0) {
        // Error handling
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return NULL;
    }

    size_t decrypted_len;
    if (EVP_PKEY_decrypt(ctx, NULL, &decrypted_len, (const unsigned char *)encrypted_message, strlen(encrypted_message)) <= 0) {
        // Error handling
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return NULL;
    }

    unsigned char *decrypted_data = (unsigned char *)malloc(decrypted_len);
    if (!decrypted_data) {
        // Error handling
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return NULL;
    }

    if (EVP_PKEY_decrypt(ctx, decrypted_data, &decrypted_len, (const unsigned char *)encrypted_message, strlen(encrypted_message)) <= 0) {
        // Error handling
        free(decrypted_data);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pub_key);
    EVP_PKEY_free(priv_key);
    
    return (char *)decrypted_data;
}

int main() {
    const char *priv_file = "private_key.pem";
    const char *pub_file = "public_key.pem";
    const char *priv_file2 = "private_key2.pem";
    const char *pub_file2 = "public_key2.pem";
    generate_dh_key_pair(pub_file, priv_file);
    generate_dh_key_pair(pub_file2, priv_file2);
    const char *message = "Hello, DH!";
    std::cout << "Original message: " << message << std::endl;

    char *encrypted_message = encrypt_dh(pub_file2, priv_file, message);
    if (encrypted_message) {
        std::cout << "Encrypted message: " << encrypted_message << std::endl;

        char *decrypted_message = decrypt_dh(pub_file, priv_file2, encrypted_message);
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