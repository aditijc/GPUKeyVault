void generate_ecdh_key_pair(const char *pub_file, const char *priv_file);

char *encrypt_ecdh(const char *pub_file, const char *message);

char *decrypt_ecdh(char *message, const char *priv_file);