// char *aes_default_keygen();
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

char *aes_encrypt(unsigned char *shared_secret, size_t shared_secret_len, const char *message);

char *aes_decrypt(unsigned char *shared_secret, const char *encrypted_message);