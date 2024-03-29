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



#include <iostream>
#include <vector>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

std::vector<unsigned char> generate_aes_key_helper();

unsigned char *aes_default_keygen(const std::vector<unsigned char>& data);


char *aes_encrypt(unsigned char *shared_secret, size_t shared_secret_len, const char *message);

char *aes_decrypt(unsigned char *shared_secret, const char *encrypted_message);

std::string generate_aes_key();

std::string aes_default_encrypt(const std::string& plainText, const std::string& key);

std::string aes_default_decrypt(const std::string& encryptedText, const std::string& key);