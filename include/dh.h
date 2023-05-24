void generate_dh_key_pair(std::string pub_file, std::string priv_file);

char *encrypt_dh(std::string pub_file, std::string priv_file, std::string message);

char *decrypt_dh(std::string pub_file, std::string priv_file, std::string encrypted_message);