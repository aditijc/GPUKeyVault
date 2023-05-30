#include <iostream>
#include <fstream>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "rsa.h"
#include "aes.h"

void generatePrimes(BIGNUM* p, BIGNUM* q) {
    BIGNUM* tmp = BN_new();
    BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL);
    do {
        BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL);
        BN_sub(tmp, p, q);
    } while (BN_is_zero(tmp) || BN_is_negative(tmp));
    BN_free(tmp);
}

bool saveKeyToPem(RSA* rsa, const std::string& filename, bool isPrivate) {
    FILE* file = fopen(filename.c_str(), "wb");
    if (!file)
        return false;

    if (isPrivate)
        PEM_write_RSAPrivateKey(file, rsa, NULL, NULL, 0, NULL, NULL);
    else
        PEM_write_RSAPublicKey(file, rsa);

    fclose(file);
    return true;
}

RSA* loadKeyFromPem(const std::string& filename, bool isPrivate) {
    RSA* rsa = NULL;
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file)
        return NULL;

    if (isPrivate)
        PEM_read_RSAPrivateKey(file, &rsa, NULL, NULL);
    else
        PEM_read_RSAPublicKey(file, &rsa, NULL, NULL);

    fclose(file);
    return rsa;
}

void rsa_keygen(const std::string priv_file, const std::string pub_file) {
    RSA* rsa = RSA_new();
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();

    // Generate prime numbers
    generatePrimes(p, q);

    // Compute RSA keys
    RSA_generate_key_ex(rsa, 2048, q, NULL);

    // Save keys to PEM files
    saveKeyToPem(rsa, priv_file, true);
    saveKeyToPem(rsa, pub_file, false);

    RSA_free(rsa);
    BN_free(p);
    BN_free(q);
}

std::string rsa_encrypt(const std::string public_file, const std::string& plaintext) {
    RSA* rsa = loadKeyFromPem(public_file.c_str(), false);
    int rsaSize = RSA_size(rsa);
    std::string ciphertext;
    ciphertext.resize(rsaSize);

    int result = RSA_public_encrypt(plaintext.size(), reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                                    reinterpret_cast<unsigned char*>(&ciphertext[0]), rsa, RSA_PKCS1_PADDING);

    if (result == -1)
        return "";

    return ciphertext;
}

std::string rsa_decrypt(const std::string private_file, const std::string& ciphertext) {
    RSA* rsa = loadKeyFromPem(private_file, true);
    int rsaSize = RSA_size(rsa);
    std::string plaintext;
    plaintext.resize(rsaSize);

    int result = RSA_private_decrypt(ciphertext.size(), reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                                     reinterpret_cast<unsigned char*>(&plaintext[0]), rsa, RSA_PKCS1_PADDING);

    if (result == -1)
        return "";

    return plaintext;
}

std::string rsa_pgp_encrypt(char **aes_encrypted_key, const std::string message, const std::string pub_key_file, const std::string priv_key_file) {
    std::string aes_key = generate_aes_key();
    // std::cout << "\n!!!aeskey: " << aes_key << std::endl;
    std::string encrypted_message = aes_default_encrypt(message, aes_key);
    std::string ekey = rsa_encrypt(pub_key_file, aes_key);
    *aes_encrypted_key = (char *) malloc(sizeof((char *)ekey.c_str()));
    *aes_encrypted_key = (char *)ekey.c_str();
    // std::cout << "\n!!!ENCRYPTEDKEY: " << *aes_encrypted_key << std::endl;
    // std::string decrypted_key = rsa_decrypt(priv_key_file, *aes_encrypted_key);
    // std::cout << "!!!DECRYPTEDKEY: " << decrypted_key << std::endl;
    return encrypted_message;
}

std::string rsa_pgp_decrypt(char *aes_encrypted_key, const std::string encrypted_message, const std::string priv_key_file) {
    // std::cout << "\n!!!ENCRYPTEDKEY: " << aes_encrypted_key << std::endl;
    std::string decrypted_key = rsa_decrypt(priv_key_file, aes_encrypted_key);
    // std::cout << "!!!DECRYPTEDKEY: " << decrypted_key << std::endl;
    std::string decrypted_message = aes_default_decrypt(encrypted_message, decrypted_key);
    return decrypted_message;
}