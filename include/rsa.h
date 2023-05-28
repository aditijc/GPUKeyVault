
#include<iostream>
#include<math.h>
#include<string.h>
#include<stdlib.h>
 
using namespace std;

int prime(long int prime_val);



char *generate_rsa_public_key(void);

char *generate_rsa_private_key(void);

char *encrypt_rsa(char *message, char *public_key);

char *decrypt_rsa(char *message, char *private_key);