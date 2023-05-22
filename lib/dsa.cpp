#include <openssl/sha.h>
#include <gmpxx.h>
#include <string>
#include <iostream>
#include "../include/dsa.h"

void generate_dsa_public_key(void) {
    int L = 2048;
    unsigned long N = 224;
    mpz_t p, q, q_lt;

    mpz_init2(q, N);
    mpz_init2(q_lt, N);
    mpz_init2(p, L);

    gmp_randstate_t rstate;
    gmp_randinit_mt(rstate);
    gmp_randseed_ui(rstate, time(NULL));

    mpz_urandomb(q_lt, rstate, N);
    mpz_nextprime(q, q_lt);
    std::cout << "Our selected prime is " << q << "\n";
}

std::string generate_dsa_private_key(void);

std::string encrypt_dsa(char *message, char *public_key);

std::string decrypt_dsa(char *message, char *private_key);

int main() {
    generate_dsa_public_key();
}