#include <string>

void generate_dsa_public_key(void);

std::string generate_dsa_private_key(void);

std::string encrypt_dsa(char *message, char *public_key);

std::string decrypt_dsa(char *message, char *private_key);