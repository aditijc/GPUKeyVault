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