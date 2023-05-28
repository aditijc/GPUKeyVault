#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <iostream>
#include <cassert>
#include <cstring>
#include "dh.h"
#include "aes.h"

// void generate_dh_key_pair(const char *pub_file, const char *priv_file) {
//     EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
//     if (ctx == NULL) {
//         std::cout << "context" << std::endl;
//     }
//     EVP_PKEY_CTX_set_dh_nid(ctx, NID_X9_62_prime256v1)
//     EVP_PKEY *pkey = NULL;
//     EVP_PKEY_keygen_init(ctx);
//     if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
//         // Error handling
//         EVP_PKEY_CTX_free(ctx);
//         std::cout << "keys not made" << std::endl;
//         return;
//     }
//     FILE *pub_fp = fopen(pub_file, "w");
//     if (!pub_fp) {
//         // Error handling
//         EVP_PKEY_CTX_free(ctx);
//         EVP_PKEY_free(pkey);
//         return;
//     }
//     PEM_write_PUBKEY(pub_fp, pkey);
//     fclose(pub_fp)
//     FILE *priv_fp = fopen(priv_file, "w");
//     if (!priv_fp) {
//         // Error handling
//         EVP_PKEY_CTX_free(ctx);
//         EVP_PKEY_free(pkey);
//         return;
//     }
//     PEM_write_PrivateKey(priv_fp, pkey, NULL, NULL, 0, NULL, NULL);
//     fclose(priv_fp)
//     EVP_PKEY_CTX_free(ctx);
//     EVP_PKEY_free(pkey);
// }

void generate_dh_key_pair(const char* pub_file, const char* priv_file) {
    DH* dh_params = DH_new();
    if (!dh_params) {
        std::cout << "Failed to create DH parameters" << std::endl;
        return;
    }

    if (DH_generate_parameters_ex(dh_params, 2048, DH_GENERATOR_2, nullptr) != 1) {
        std::cout << "Failed to generate DH parameters" << std::endl;
        DH_free(dh_params);
        return;
    }

    if (!dh_params) {
        std::cout << "Failed to read DH parameters" << std::endl;
        return;
    }

    EVP_PKEY* evp_pubkey = EVP_PKEY_new();
    EVP_PKEY* evp_privkey = EVP_PKEY_new();

    if (!evp_pubkey || !evp_privkey) {
        std::cout << "Failed to allocate memory for DH key pair" << std::endl;
        DH_free(dh_params);
        EVP_PKEY_free(evp_pubkey);
        EVP_PKEY_free(evp_privkey);
        return;
    }

    if (DH_generate_key(dh_params) == 0) {
        std::cout << "Failed to generate DH key pair" << std::endl;
        DH_free(dh_params);
        EVP_PKEY_free(evp_pubkey);
        EVP_PKEY_free(evp_privkey);
        return;
    }

    EVP_PKEY_assign_DH(evp_pubkey, DH_new());
    EVP_PKEY_assign_DH(evp_privkey, DH_new());

    EVP_PKEY_set1_DH(evp_pubkey, dh_params);
    EVP_PKEY_set1_DH(evp_privkey, dh_params);

    FILE* pub_fp = fopen(pub_file, "w");
    if (!pub_fp) {
        std::cout << "Failed to open public key file" << std::endl;
        DH_free(dh_params);
        EVP_PKEY_free(evp_pubkey);
        EVP_PKEY_free(evp_privkey);
        return;
    }

    if (PEM_write_PUBKEY(pub_fp, evp_pubkey) == 0) {
        std::cout << "Failed to write public key" << std::endl;
    }

    fclose(pub_fp);

    FILE* priv_fp = fopen(priv_file, "w");
    if (!priv_fp) {
        std::cout << "Failed to open private key file" << std::endl;
        DH_free(dh_params);
        EVP_PKEY_free(evp_pubkey);
        EVP_PKEY_free(evp_privkey);
        return;
    }

    if (PEM_write_PrivateKey(priv_fp, evp_privkey, nullptr, nullptr, 0, nullptr, nullptr) == 0) {
        std::cout << "Failed to write private key" << std::endl;
    }

    fclose(priv_fp);

    DH_free(dh_params);
    EVP_PKEY_free(evp_pubkey);
    EVP_PKEY_free(evp_privkey);

    std::cout << "DH key pair generated and saved successfully" << std::endl;
}

char *encrypt_dh(const char *pub_file, const char *priv_file, const char *message) {
    OpenSSL_add_all_algorithms();
    FILE *pub_fp = fopen(pub_file, "r");
    if (!pub_fp) {
        // Error handling
        perror("Failed to open public key file");
        return NULL;
    }
    
    EVP_PKEY *pub_key = PEM_read_PUBKEY(pub_fp, NULL, NULL, NULL);
    fclose(pub_fp);

    FILE *priv_fp = fopen(priv_file, "r");
    if (!priv_fp) {
        // Error handling
        perror("Failed to open private key file");
        EVP_PKEY_free(pub_key);
        return NULL;
    }
    
    EVP_PKEY *priv_key = PEM_read_PrivateKey(priv_fp, NULL, NULL, NULL);
    fclose(priv_fp);

    if (!priv_key) {
        std::cerr << "Encryption Error: Failed to read private key." << std::endl;
        return NULL;
    }
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        // Error handling
        std::cerr << "Failed to create EVP_PKEY_CTX." << std::endl;
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return NULL;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        // Handle error
        std::cerr << "Failed to initialize key derivation." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return nullptr;
    }
    // Provide the peer's public key to the context
    if (EVP_PKEY_derive_set_peer(ctx, pub_key) <= 0) {
        // Handle error
        std::cerr << "Failed to set peer's public key." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return nullptr;
    }
    // Determine the size of the shared secret
    size_t shared_secret_len;
    if (EVP_PKEY_derive(ctx, NULL, &shared_secret_len) <= 0) {
        // Handle error
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return nullptr;
    }
    // Allocate memory for the shared secret
    unsigned char* shared_secret = new unsigned char[shared_secret_len];

    // Derive the shared secret
    if (EVP_PKEY_derive(ctx, shared_secret, &shared_secret_len) <= 0) {
        // Handle error
        delete[] shared_secret;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pub_key);
        EVP_PKEY_free(priv_key);
        return nullptr;
    }

    // Clean up memory
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pub_key);
    EVP_PKEY_free(priv_key);

    return aes_encrypt(shared_secret, shared_secret_len, message);

    // if (EVP_PKEY_encrypt(ctx, NULL, NULL, (const unsigned char *)message, strlen(message)) <= 0) {
    //     // Error handling
    //     EVP_PKEY_CTX_free(ctx);
    //     EVP_PKEY_free(pub_key);
    //     EVP_PKEY_free(priv_key);
    //     std::cout << "initiate context" << std::endl;
    //     return NULL;
    // }
    // size_t encrypted_len;
    // if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_len, (const unsigned char *)message, strlen(message)) <= 0) {
    //     // Error handling
    //     EVP_PKEY_CTX_free(ctx);
    //     EVP_PKEY_free(pub_key);
    //     EVP_PKEY_free(priv_key);
    //     return NULL;
    // }

    // unsigned char *encrypted_data = (unsigned char *)malloc(encrypted_len);
    // if (!encrypted_data) {
    //     // Error handling
    //     EVP_PKEY_CTX_free(ctx);
    //     EVP_PKEY_free(pub_key);
    //     EVP_PKEY_free(priv_key);
    //     return NULL;
    // }

    // if (EVP_PKEY_encrypt(ctx, encrypted_data, &encrypted_len, (const unsigned char *)message, strlen(message)) <= 0) {
    //     // Error handling
    //     free(encrypted_data);
    //     EVP_PKEY_CTX_free(ctx);
    //     EVP_PKEY_free(pub_key);
    //     EVP_PKEY_free(priv_key);
    //     return NULL;
    // }

    // EVP_PKEY_CTX_free(ctx);
    // EVP_PKEY_free(pub_key);
    // EVP_PKEY_free(priv_key);
    
    // return (char *)encrypted_data;
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
    std::cout << "Original message: " << std::endl;

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
    // generate_dh_key_pair(pub_file, priv_file);
    // generate_dh_key_pair(pub_file2, priv_file2);
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