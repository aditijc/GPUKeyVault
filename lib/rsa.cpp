#include <iostream>
#include <fstream>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

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

std::string encrypt(RSA* rsa, const std::string& plaintext) {
    int rsaSize = RSA_size(rsa);
    std::string ciphertext;
    ciphertext.resize(rsaSize);

    int result = RSA_public_encrypt(plaintext.size(), reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                                    reinterpret_cast<unsigned char*>(&ciphertext[0]), rsa, RSA_PKCS1_PADDING);

    if (result == -1)
        return "";

    return ciphertext;
}

std::string decrypt(RSA* rsa, const std::string& ciphertext) {
    int rsaSize = RSA_size(rsa);
    std::string plaintext;
    plaintext.resize(rsaSize);

    int result = RSA_private_decrypt(ciphertext.size(), reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                                     reinterpret_cast<unsigned char*>(&plaintext[0]), rsa, RSA_PKCS1_PADDING);

    if (result == -1)
        return "";

    return plaintext;
}

int main() {
    RSA* rsa = RSA_new();
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();

    // Generate prime numbers
    generatePrimes(p, q);

    // Compute RSA keys
    RSA_generate_key_ex(rsa, 2048, q, NULL);

    // Save keys to PEM files
    saveKeyToPem(rsa, "private_key.pem", true);
    saveKeyToPem(rsa, "public_key.pem", false);

    RSA_free(rsa);
    BN_free(p);
    BN_free(q);

    // Load keys from PEM files
    RSA* privateKey = loadKeyFromPem("private_key.pem", true);
    RSA* publicKey = loadKeyFromPem("public_key.pem", false);

    std::string plaintext = "Hello, RSA!";
    std::string encrypted = encrypt(publicKey, plaintext);
    std::string decrypted = decrypt(privateKey, encrypted);

    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Encrypted: " << encrypted << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;

    RSA_free(privateKey);
    RSA_free(publicKey);

    return 0;
}
