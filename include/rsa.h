#include <iostream>
#include <fstream>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
 
using namespace std;

void rsa_keygen();

RSA* loadKeyFromPem(const std::string& filename, bool isPrivate);

std::string rsa_encrypt(RSA* rsa, const std::string& plaintext);

std::string rsa_decrypt(RSA* rsa, const std::string& ciphertext);