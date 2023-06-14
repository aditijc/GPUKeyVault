#include <iostream>
#include <chrono>
#include <vector>
#include <cmath>
#include <numeric>
#include "ecdh.h"
#include "aes.h"
#include "rsa.h"

using namespace std::chrono;

const int N = 100;

float compute_mean(std::vector<int64_t> v) {
    return std::reduce(v.begin(), v.end()) / N;
}

void time_rsa() {
    std::cout << "Performing RSA CPU key generation." << std::endl;

    std::vector<int64_t> cpu_keygen_times;
    std::vector<int64_t> gpu_keygen_times;
    for (int i = 0; i < N; i++) {
        auto start = high_resolution_clock::now();
        rsa_keygen(
            "private-keys/rsa_private_demo.pem", 
            "public-keys/rsa_public_demo.pem");
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        int64_t dt = duration.count();
        cpu_keygen_times.push_back(dt);
    }

    // for (int i = 0; i < N; i++) {
    //     auto start = high_resolution_clock::now();
    //     // GPU code
    //     auto stop = high_resolution_clock::now();
    //     auto duration = duration_cast<microseconds>(stop - start);
    //     int64_t dt = duration.count();
    //     std::cout << dt << std::endl;
    //     gpu_keygen_times.push_back(dt);
    // }

    std::vector<int64_t> cpu_en_times;
    std::vector<int64_t> cpu_de_times;
    std::vector<int64_t> gpu_en_times;
    std::vector<int64_t> gpu_de_times;
    const std::string pub_file = "public-keys/rsa_public_demo.pem";
    const std::string priv_file = "private-keys/rsa_private_demo.pem";
    const std::string plaintext = "the quick brown fox jumps over the lazy dog";

    std::cout << "Performing RSA encryption and decryption." << std::endl;

    for (int i = 0; i < N; i++) {
        auto start = high_resolution_clock::now();
        std::string encrypted = rsa_encrypt(pub_file, plaintext);
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        cpu_en_times.push_back(duration.count());

        start = high_resolution_clock::now();
        std::string decrypted = rsa_decrypt(priv_file, encrypted);
        stop = high_resolution_clock::now();
        duration = duration_cast<microseconds>(stop - start);
        cpu_de_times.push_back(duration.count());
    }

    // for (int i = 0; i < N; i++) {
    //     auto start = high_resolution_clock::now();
    //     std::string encrypted = ""; // GPU CODE
    //     auto stop = high_resolution_clock::now();
    //     auto duration = duration_cast<microseconds>(stop - start);
    //     gpu_en_times.push_back(duration.count());

    //     start = high_resolution_clock::now();
    //     std::string decrypted = ""; // GPU CODE
    //     stop = high_resolution_clock::now();
    //     duration = duration_cast<microseconds>(stop - start);
    //     gpu_de_times.push_back(duration.count());
    // }

    std::ofstream cpu_csvfile("results/rsa_cpu.csv");
    cpu_csvfile << "CPU keygen,CPU encryption,CPU decryption" << endl;
    for (int i = 0; i < N; i++) {
        cpu_csvfile << cpu_keygen_times[i] << "," << cpu_en_times[i] << "," << cpu_de_times[i] << endl;
    }

    std::ofstream gpu_csvfile("results/rsa_gpu.csv");
    gpu_csvfile << "GPU keygen,GPU encryption,GPU decryption" << endl;
    // for (int i = 0; i < N; i++) {
    //     gpu_csvfile << gpu_keygen_times[i] << "," << gpu_en_times[i] << "," << gpu_de_times[i] << endl;
    // }

    std::ofstream rsa_res("results/rsa_results.txt");
    rsa_res << "CPU keygen: " << compute_mean(cpu_keygen_times) << " µs" << endl;
    rsa_res << "GPU keygen: " << compute_mean(gpu_keygen_times) << " µs" << endl;
    rsa_res << "CPU encryption: " << compute_mean(cpu_en_times) << " µs" << endl;
    rsa_res << "GPU encryption: " << compute_mean(gpu_en_times) << " µs" << endl;
    rsa_res << "CPU decryption: " << compute_mean(cpu_de_times) << " µs" << endl;
    rsa_res << "GPU decryption: " << compute_mean(gpu_de_times) << " µs" << endl;

}

int main() {
    std::cout << "Timing RSA" << std::endl; 
    time_rsa();
    return 0;
}