char *generate_ecdsa_key_pair(void);

char *encrypt_ecdsa(char *message, char *public_key);

char *decrypt_ecdsa(char *message, char *private_key);