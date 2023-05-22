#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <iostream>
#include <cassert>
#include "../include/ecdsa.h"

char *generate_ecdsa_key_pair(char *pub_file, char *priv_file) {
    ECDSA_SIG *signature = ECDSA_SIG_new();
    ECDSA_SIG_free(signature);
    // TODO: Figure out why signatures are useful
    EC_KEY *ec_key = EC_KEY_new();
    assert(1==EC_KEY_generate_key(ec_key));
    assert(1==EC_KEY_check_key(ec_key));

    FILE * f = fopen(pub_file,"w");
    PEM_write_EC_PUBKEY(f, ec_key);
    fclose(f);

    FILE * f = fopen(priv_file,"w");
    PEM_write_ECPrivateKey(f,ec_key, NULL,NULL,0,NULL,NULL);
    fclose(f);

    EC_KEY_free(ec_key);
}

char *encrypt_ecdsa(char *message, char *public_key) {

}

char *decrypt_ecdsa(char *message, char *private_key) {

}