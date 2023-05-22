char *generate_ecdsa_public_key(void);

char *generate_ecdsa_private_key(void);

char *encrypt_ecdsa(char *message, char *public_key);

char *decrypt_ecdsa(char *message, char *private_key);