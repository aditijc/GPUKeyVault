#include <iostream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h> // Include the Buffer header
#include <cstring>
#include <string>
#include <vector>


// need to figure out what to do with the IV thing --> has to be generated for every
// plain text that we want to encrypt + every cipher we want to ecrypt

// OR we can use the same intialization string for the IV each time

// Make sure to provide the key and IV strings in the correct format (e.g., hexadecimal) 
// and with the appropriate lengths (32-byte key for AES-256 and 16-byte IV for AES-256 CBC).

const int AES_KEY_SIZE = 256;  // AES-256

std::string generate_aes_key() {
    std::vector<unsigned char> key(AES_KEY_SIZE / 8);

    // Generate the AES key
    if (RAND_bytes(key.data(), key.size()) != 1) {
        std::cerr << "Error generating AES key." << std::endl;
        // Handle the error case appropriately
    }

    return std::string(key.begin(), key.end());
}


// Function to perform AES encryption
std::string encrypt(const std::string& algorithm, const std::string& input,
                    const std::string& keyStr, const std::string& ivStr) {
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(algorithm.c_str());
    if (cipher == nullptr) {
        std::cerr << "Unsupported algorithm: " << algorithm << std::endl;
        // Handle error appropriately
    }

    std::vector<unsigned char> key(keyStr.begin(), keyStr.end());
    std::vector<unsigned char> iv(ivStr.begin(), ivStr.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        std::cerr << "Error creating cipher context." << std::endl;
        // Handle error appropriately
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) != 1) {
        std::cerr << "Error initializing encryption." << std::endl;
        // Handle error appropriately
    }

    std::vector<unsigned char> ciphertext(input.size() + AES_BLOCK_SIZE);
    int ciphertextLen = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphertextLen,
                          reinterpret_cast<const unsigned char*>(input.c_str()), input.size()) != 1) {
        std::cerr << "Error performing encryption." << std::endl;
        // Handle error appropriately
    }

    int finalCiphertextLen = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertextLen, &finalCiphertextLen) != 1) {
        std::cerr << "Error finalizing encryption." << std::endl;
        // Handle error appropriately
    }

    ciphertextLen += finalCiphertextLen;

    EVP_CIPHER_CTX_free(ctx);

    std::string encodedCiphertext = base64Encode(ciphertext.data(), ciphertextLen);

    return encodedCiphertext;
}




// Function to perform base64 encoding
std::string base64Encode(const unsigned char* data, int size) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);
    BIO_write(b64, data, size);
    BIO_flush(b64);

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(b64, &mem);

    std::string encodedString(mem->data, mem->length);

    BIO_free_all(b64);

    return encodedString;
}







// Function to perform AES decryption
std::string decrypt(const std::string& algorithm, const std::string& cipherText,
                    const std::string& keyStr, const std::string& ivStr) {
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(algorithm.c_str());
    if (cipher == nullptr) {
        std::cerr << "Unsupported algorithm: " << algorithm << std::endl;
        // Handle error appropriately
    }

    std::vector<unsigned char> key(keyStr.begin(), keyStr.end());
    std::vector<unsigned char> iv(ivStr.begin(), ivStr.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        std::cerr << "Error creating cipher context." << std::endl;
        // Handle error appropriately
    }

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) != 1) {
        std::cerr << "Error initializing decryption." << std::endl;
        // Handle error appropriately
    }

    std::vector<unsigned char> decryptedText(cipherText.size());
    int decryptedTextLen = 0;

    if (EVP_DecryptUpdate(ctx, decryptedText.data(), &decryptedTextLen,
                          reinterpret_cast<const unsigned char*>(cipherText.c_str()), cipherText.size()) != 1) {
        std::cerr << "Error performing decryption." << std::endl;
        // Handle error appropriately
    }

    int finalDecryptedTextLen = 0;
    if (EVP_DecryptFinal_ex(ctx, decryptedText.data() + decryptedTextLen, &finalDecryptedTextLen) != 1) {
        std::cerr << "Error finalizing decryption." << std::endl;
        // Handle error appropriately
    }

    decryptedTextLen += finalDecryptedTextLen;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(decryptedText.begin(), decryptedText.begin() + decryptedTextLen); // Convert vector to string

}



// // AES key generation tester
// int main() {
//     std::string aesKey = generate_aes_key();

//     std::cout << "AES Key: " << aesKey << std::endl;

//     return 0;
// }




// //tester for decryption
// int main() {
//     // Test data
//     std::string algorithm = "aes-256-cbc";
//     std::string cipherText = "j3oNqN9tj+nm2kZO+5fWqg==";  // Encrypted text in base64
//     std::string keyStr = "0123456789abcdef0123456789abcdef";  // 32-byte key in hexadecimal
//     std::string ivStr = "0123456789abcdef";  // 16-byte IV in hexadecimal

//     std::string decryptedText = decrypt(algorithm, cipherText, keyStr, ivStr);

//     std::cout << "Decrypted Text: " << decryptedText << std::endl;

//     return 0;
// }


// // tester for encryption 
// int main() {
//     // Test data
//     std::string algorithm = "aes-256-cbc";
//     std::string input = "Hello, World!";
//     std::string keyStr = "0123456789abcdef0123456789abcdef";  // 32-byte key in hexadecimal
//     std::string ivStr = "0123456789abcdef";  // 16-byte IV in hexadecimal

//     std::string encryptedText = encrypt(algorithm, input, keyStr, ivStr);

//     std::cout << "Encrypted Text: " << encryptedText << std::endl;

//     return 0;
// }
