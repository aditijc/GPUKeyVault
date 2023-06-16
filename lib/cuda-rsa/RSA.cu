#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <string.h>
#include <math.h>
#include "RSA.h"

__device__
long long int mod(int base, int exponent, int den)
{
    long long int ret = 1;

    for (int i = 0; i < exponent; i++)
    {
        ret *= base;
        ret %= den;
    }

    return ret;
}

__global__
void rsa(int* num, int* key, int* den, int* result)
{
    int i = blockDim.x * blockIdx.x + threadIdx.x;
    int temp;

    temp = mod(num[i], *key, *den);
    atomicExch(&result[i], temp);
}


// #define BS 100

// int p, q, n, t, numChars, tpb = 1024;
// int bpg;
// int e[BS], d[BS], temp[BS], j, m[BS],
//     en[BS], mm[BS], res[BS], i;

// float time_enc_gpu, time_dec_gpu = 0.0;

// char msg[BS];

int p, q, n, t, numChars, tpb = 1024;
int bpg;
int* e, *d, *temp, j, *m, *en, *mm, *res, i;

float time_enc_gpu, time_dec_gpu = 0.0;

char* msg;

int getFileSize(const std::string& filename) {
    std::ifstream file(filename, std::ifstream::ate | std::ifstream::binary);
    if (!file.is_open()) {
        return -1; // Return -1 if there was an error opening the file
    }

    return static_cast<int>(file.tellg());
}


int main(int argc, char* argv[]) {
    p = 157;
    q = 373;

    std::string filePath = argv[1];
    int fileSize = getFileSize(filePath);
    if (fileSize == -1) {
        std::cout << "Error opening the file." << std::endl;
        return 1;
    }

    int BS = fileSize;

    e = new int[BS];
    d = new int[BS];
    temp = new int[BS];
    j = 0;
    m = new int[BS];
    en = new int[BS];
    mm = new int[BS];
    res = new int[BS];
    i = 0;

    msg = new char[BS];

    srand((unsigned) time(NULL));

    msg = new char[BS + 1]; // Allocate space for BS characters plus the null terminator

    std::ifstream inputFile(filePath);
    if (!inputFile.is_open()) {
        std::cout << "Error opening the file." << std::endl;
        delete[] msg; // Clean up dynamically allocated memory
        return 1;
    }

    inputFile.read(msg, BS); // Read BS characters from the file

    numChars = strlen(msg) - 1;
    msg[numChars] = '\0'; // Add null terminator to end of string
    inputFile.close();

    bpg = (numChars + tpb - 1) / tpb;

    for (i = 0; msg[i] != '\0'; i++) {
        m[i] = msg[i];
        mm[i] = msg[i] - 96;
    }

    n = p * q;
    t = (p - 1) * (q - 1);
    fc();

    enc_gpu();
    dec_gpu();
    return 0;
}

void fc() {
    int k = 0;
    long int kv = 1;
    for (int i = 2; i < t && k < 99; i++) {
        if (t % i == 0)
            continue;
        bool ip = true;
        int j = sqrt(i);
        for (int mn = 2; mn <= j; mn++) {
            if (i % mn == 0) {
                ip = false;
                break;
            }
        }
        if (ip && i != p && i != q) {
            e[k] = i;
            long int x = e[k];
            while (true) {
                kv = kv + t;
                if (kv % x == 0) {
                    d[k] = kv / x;
                    k++;
                    break;
                }
            }
        }
    }
}
void enc_gpu() {
    // Allocate and copy memory on the GPU
    cudaSetDevice(1);
    
    int key = e[0];
    int *dev_num, *dev_key, *dev_den, *dev_res;
    
    cudaMalloc((void**)&dev_num, numChars * sizeof(int));
    cudaMalloc((void**)&dev_key, sizeof(int));
    cudaMalloc((void**)&dev_den, sizeof(int));
    cudaMalloc((void**)&dev_res, numChars * sizeof(int));
    
    cudaMemcpy(dev_num, mm, numChars * sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_key, &key, sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_den, &n, sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_res, res, numChars * sizeof(int), cudaMemcpyHostToDevice);
    
    // Encryption on the GPU
    cudaEvent_t start_encrypt, stop_encrypt;
    cudaEventCreate(&start_encrypt);
    cudaEventCreate(&stop_encrypt);
    cudaEventRecord(start_encrypt);
    
    rsa<<<bpg, tpb>>>(dev_num, dev_key, dev_den, dev_res);
    
    cudaEventRecord(stop_encrypt);
    cudaEventSynchronize(stop_encrypt);
    cudaThreadSynchronize();
    
    // Calculate elapsed time
    float time_enc_gpu = 0;
    cudaEventElapsedTime(&time_enc_gpu, start_encrypt, stop_encrypt);
    time_enc_gpu /= 1000;
    
    // Copy the result back to host and free GPU memory
    cudaMemcpy(res, dev_res, numChars * sizeof(int), cudaMemcpyDeviceToHost);
    
    cudaFree(dev_num);
    cudaFree(dev_key);
    cudaFree(dev_den);
    cudaFree(dev_res);
    
    // Write encrypted result to a file
    FILE *fp = fopen("encrypted_gpu.txt", "wb");
    if (fp != NULL) {
        for (int i = 0; i < numChars; i++) {
            fprintf(fp, "%d", res[i] + 96);
        }
        fclose(fp);
    }
}

void dec_gpu() {
    // Allocate and copy memory on the GPU
    cudaSetDevice(1);
    
    int key = d[0];
    int *dev_num, *dev_key, *dev_den, *dev_res;
    
    cudaMalloc((void**)&dev_num, numChars * sizeof(int));
    cudaMalloc((void**)&dev_key, sizeof(int));
    cudaMalloc((void**)&dev_den, sizeof(int));
    cudaMalloc((void**)&dev_res, numChars * sizeof(int));
    
    cudaMemcpy(dev_num, res, numChars * sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_key, &key, sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_den, &n, sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(dev_res, res, numChars * sizeof(int), cudaMemcpyHostToDevice);
    
    // Decryption on the GPU
    cudaEvent_t start_decrypt, stop_decrypt;
    cudaEventCreate(&start_decrypt);
    cudaEventCreate(&stop_decrypt);
    cudaEventRecord(start_decrypt);
    
    printf("GPU starts decrypting...\n");
    rsa<<<bpg, tpb>>>(dev_num, dev_key, dev_den, dev_res);
    
    cudaEventRecord(stop_decrypt);
    cudaEventSynchronize(stop_decrypt);
    cudaThreadSynchronize();
    
    // Calculate elapsed time
    float time_dec_gpu = 0;
    cudaEventElapsedTime(&time_dec_gpu, start_decrypt, stop_decrypt);
    time_dec_gpu /= 1000;
    
    // Copy the result back to host and free GPU memory
    cudaMemcpy(res, dev_res, numChars * sizeof(int), cudaMemcpyDeviceToHost);
    
    cudaFree(dev_num);
    cudaFree(dev_key);
    cudaFree(dev_den);
    cudaFree(dev_res);
    
    // Write decrypted result to a file
    FILE *fp = fopen("decrypted_gpu.txt", "wb");
    if (fp != NULL) {
        for (int i = 0; i < numChars; i++) {
            fprintf(fp, "%c", res[i] + 96);
        }
        fprintf(fp, "\n");
        fclose(fp);
    }
}
