void generate_dh_key_pair(const char* pub_file, const char* priv_file);

char *encrypt_dh(std::string pub_file, std::string priv_file, std::string message);

char *decrypt_dh(std::string pub_file, std::string priv_file, std::string encrypted_message);