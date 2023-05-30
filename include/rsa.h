#include <iostream>
#include <fstream>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
 
using namespace std;

void rsa_keygen(const std::string priv_file, const std::string pub_file);

RSA* loadKeyFromPem(const std::string& filename, bool isPrivate);

std::string rsa_encrypt(const std::string public_file, const std::string& plaintext);

std::string rsa_decrypt(const std::string private_file, const std::string& ciphertext);

std::string rsa_pgp_encrypt(std::string *aes_encrypted_key, const std::string message, const std::string pub_key_file);

std::string rsa_pgp_decrypt(std::string aes_encrypted_key, const std::string encrypted_message, const std::string priv_key_file);