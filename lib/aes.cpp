#include <iostream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h> // Include the Buffer header
#include <cstring>
#include <string>
#include <vector>



const int AES_KEY_SIZE = 256;  // AES-256


char *aes_encrypt(unsigned char *shared_secret, size_t shared_secret_len, const char *message) {
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int block_size = EVP_CIPHER_block_size(cipher);
    EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
    if (!aes_ctx) {
        std::cerr << "Encryption Error: Failed to create encryption context." << std::endl;
        // EC_KEY_free(ec_pubkey);
        delete[] shared_secret;
        return nullptr;
    }

    unsigned char iv[block_size];
    memset(iv, 0, sizeof(iv));

    unsigned char *ciphertext = new unsigned char[shared_secret_len + block_size];
    int ciphertext_len = 0;


    // Parallelize the AES encryption process on the GPU using CUDA.

    // 1. Transfer the necessary data (shared_secret, message, iv) from the CPU to the GPU device memory.

    // 2. Launch a CUDA kernel to perform AES encryption on multiple data elements in parallel.
    //    Each CUDA thread can handle one block of data or a portion of the data, ensuring efficient parallel execution.

    // 3. Within the CUDA kernel, perform the AES encryption using the EVP_EncryptUpdate and EVP_EncryptFinal_ex functions.

    if (EVP_EncryptInit_ex(aes_ctx, cipher, NULL, shared_secret, iv) != 1 ||
        EVP_EncryptUpdate(aes_ctx, ciphertext, &ciphertext_len, reinterpret_cast<const unsigned char *>(message),
        strlen(message)) != 1 || EVP_EncryptFinal_ex(aes_ctx, ciphertext + ciphertext_len, &ciphertext_len) != 1) {
        std::cerr << "Encryption failed." << std::endl;
        delete[] shared_secret;
        delete[] ciphertext;
        EVP_CIPHER_CTX_free(aes_ctx);
        return nullptr;
    }

    EVP_CIPHER_CTX_free(aes_ctx);
    delete[] shared_secret;
    return reinterpret_cast<char *>(ciphertext);
}


// Function to perform AES decryption using CUDA
char *aes_decrypt(unsigned char *shared_secret, const char *encrypted_message) {
    // Perform symmetric decryption using the shared secret
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int block_size = EVP_CIPHER_block_size(cipher);
    EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
    if (!aes_ctx) {
        std::cerr << "Failed to create decryption context." << std::endl;
        delete[] shared_secret;
        return nullptr;
    }

    unsigned char iv[block_size];
    memset(iv, 0, sizeof(iv));

    unsigned char *plaintext = new unsigned char[strlen(encrypted_message) + block_size];
    int plaintext_len = 0;


    // Parallelize the AES decryption process on the GPU using CUDA.

    // 1. Transfer the necessary data (shared_secret, encrypted_message, iv) from the CPU to the GPU device memory.

    // 2. Launch a CUDA kernel to perform AES decryption on multiple data elements in parallel.
    //    Each CUDA thread can handle one block of data or a portion of the data, ensuring efficient parallel execution.

    // 3. Within the CUDA kernel, perform the AES decryption using the EVP_DecryptUpdate and EVP_DecryptFinal_ex functions.

    if (EVP_DecryptInit_ex(aes_ctx, cipher, NULL, shared_secret, iv) != 1 ||
        EVP_DecryptUpdate(aes_ctx, plaintext, &plaintext_len, reinterpret_cast<const unsigned char *>(encrypted_message),
                          strlen(encrypted_message)) != 1 ||
        EVP_DecryptFinal_ex(aes_ctx, plaintext + plaintext_len, &plaintext_len) != 1) {
        std::cerr << "Decryption failed." << std::endl;
        delete[] shared_secret;
        delete[] plaintext;
        EVP_CIPHER_CTX_free(aes_ctx);
        return nullptr;
    }

    EVP_CIPHER_CTX_free(aes_ctx);
    delete[] shared_secret;
    return reinterpret_cast<char *>(plaintext);
}


// Function to generate an AES key
std::string generate_aes_key() {
    std::vector<unsigned char> key(AES_KEY_SIZE / 8);

     // Generate the AES key

    // Parallelize the key generation process on the GPU using CUDA.

    // 1. Allocate memory on the GPU device for the key.

    // 2. Launch a CUDA kernel to generate the AES key in parallel.
    //    Each CUDA thread can generate a portion of the key, ensuring efficient parallel execution.

    // 3. Transfer the generated key back from the GPU device memory to the CPU memory.
    
    if (RAND_bytes(key.data(), key.size()) != 1) {
        std::cerr << "Error generating AES key." << std::endl;
        // Handle the error case appropriately
    }

    return std::string(key.begin(), key.end());
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

// Encrypts the plain text using AES-256 encryption
// This function can be parallelized on the GPU using CUDA.
std::string aes_default_encrypt(const std::string& plainText, const std::string& key) {
    const int AES_KEY_SIZE = 256;
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

    AES_KEY aesKey;
    if (AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), AES_KEY_SIZE, &aesKey) < 0) {
        std::cerr << "Error: Failed to set encryption key." << std::endl;
        return "";
    }

    std::string encryptedText;

    int cipherLength = ((plainText.length() / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    unsigned char* cipherText = new unsigned char[cipherLength];

    // Parallelize the AES encryption process on the GPU using CUDA.

    // 1. Transfer the necessary data (plain text, key, initialization vector) from the CPU to the GPU device memory.

    // 2. Launch a CUDA kernel to perform AES encryption on multiple data elements in parallel.
    //    Each CUDA thread can handle one block of data or a portion of the data, ensuring efficient parallel execution.

    // 3. Within the CUDA kernel, perform the AES encryption using the AES_cbc_encrypt function.

    AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(plainText.c_str()), cipherText, plainText.length(),
                    &aesKey, iv, AES_ENCRYPT);
    
    // 4. Transfer the resulting cipher text back from the GPU device memory to the CPU memory.

    encryptedText.assign(reinterpret_cast<char*>(cipherText), cipherLength);

    delete[] cipherText;

    return encryptedText;
}

// Decrypts the encrypted text using AES-256 decryption
// This function can be parallelized on the GPU using CUDA.
std::string aes_default_decrypt(const std::string& encryptedText, const std::string& key) {
    const int AES_KEY_SIZE = 256;
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

    AES_KEY aesKey;
    if (AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), AES_KEY_SIZE, &aesKey) < 0) {
        std::cerr << "Error: Failed to set decryption key." << std::endl;
        return "";
    }

    std::string decryptedText;

    int plainLength = encryptedText.length();
    unsigned char* plainText = new unsigned char[plainLength];


    // Parallelize the AES decryption process on the GPU using CUDA.

    // 1. Transfer the necessary data (encrypted text, key, initialization vector) from the CPU to the GPU device memory.

    // 2. Launch a CUDA kernel to perform AES decryption on multiple data elements in parallel.
    //    Each CUDA thread can handle one block of data or a portion of the data, ensuring efficient parallel execution.

    // 3. Within the CUDA kernel, perform the AES decryption using the AES_cbc_encrypt function.

    AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(encryptedText.c_str()), plainText, plainLength,
                    &aesKey, iv, AES_DECRYPT);

    // 4. Transfer the resulting plain text back from the GPU device memory to the CPU memory.

    decryptedText.assign(reinterpret_cast<char*>(plainText), plainLength);

    delete[] plainText;

    return decryptedText;
}