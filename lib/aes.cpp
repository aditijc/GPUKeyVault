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
#include <vector>
#include <openssl/rand.h>
#include "aes.h"

// AES key size in bits
const int AES_KEY_SIZE = 256;  // 256 bits

// char *aes_default_keygen() {
//     // generates default symmetric session key and returns

// }

std::vector<unsigned char> generate_aes_key_helper() {
    std::vector<unsigned char> key(AES_KEY_SIZE / 8);

    // Generate the AES key
    if (RAND_bytes(key.data(), key.size()) != 1) {
        std::cerr << "Error generating AES key." << std::endl;
        // Handle the error case appropriately
    }

    return key;
}

unsigned char *aes_default_keygen(const std::vector<unsigned char>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);
    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);

    char* encodedData;
    long length = BIO_get_mem_data(bio, &encodedData);
    std::string base64Data(encodedData, length);

    BIO_free_all(b64);
    unsigned char* data = reinterpret_cast<unsigned char*>(base64Data.data());
    return data;
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
        strlen(message)) != 1 || EVP_EncryptFinal_ex(aes_ctx, ciphertext + ciphertext_len, &ciphertext_len) != 1) {
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
    unsigned char *shared_secret = reinterpret_cast<unsigned char*>(shared_secret_string.data());
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