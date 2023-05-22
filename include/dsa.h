char *generate_dsa_public_key(void);

char *generate_dsa_private_key(void);

char *encrypt_dsa(char *message, char *public_key);

char *decrypt_dsa(char *message, char *private_key);