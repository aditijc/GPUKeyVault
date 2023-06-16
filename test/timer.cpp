#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <vector>
#include <cmath>
#include <numeric>
#include "rsa.h"
#include "cursa.h"

using namespace std::chrono;

const int N = 100;
const char *FILE_PATH = "sample/novel.txt";

float compute_mean(std::vector<int64_t> v) {
    return std::reduce(v.begin(), v.end()) / N;
}

void time_rsa() {
    std::cout << "Performing RSA CPU key generation." << std::endl;

    std::vector<int64_t> cpu_keygen_times;
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

    std::vector<int64_t> cpu_en_times;
    std::vector<int64_t> cpu_de_times;
    const std::string pub_file = "public-keys/rsa_public_demo.pem";
    const std::string priv_file = "private-keys/rsa_private_demo.pem";

    std::ifstream t(FILE_PATH);
    std::stringstream buffer;
    buffer << t.rdbuf();
    
    const std::string plaintext = buffer.str();

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

    std::ofstream cpu_csvfile("results/rsa_cpu.csv");
    cpu_csvfile << "CPU keygen,CPU encryption,CPU decryption" << endl;
    for (int i = 0; i < N; i++) {
        cpu_csvfile << cpu_keygen_times[i] << "," << cpu_en_times[i] << "," << cpu_de_times[i] << endl;
    }

    std::cout << "Performing RSA on GPU." << std::endl;
    std::vector<int64_t> gpu_times;
    for (int i = 0; i < N; i++) {
        std::string file_path = FILE_PATH;
        auto start = high_resolution_clock::now();
        set_rsa_parameters(file_path);
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
        gpu_times.push_back(duration.count());
    }

    std::ofstream gpu_csvfile("results/rsa_gpu.csv");
    gpu_csvfile << "GPU keygen + GPU encryption + GPU decryption" << endl;
    for (int i = 0; i < N; i++) {
        gpu_csvfile << gpu_times[i] << endl;
    }

    std::ofstream rsa_res("results/rsa_results.txt");
    float ck_mean = compute_mean(cpu_keygen_times);
    float ce_mean = compute_mean(cpu_en_times);
    float cd_mean = compute_mean(cpu_de_times);
    float gpu_mean = compute_mean(gpu_times);
    rsa_res << "CPU keygen: " << ck_mean << " µs" << endl;
    rsa_res << "CPU encryption: " << ce_mean << " µs" << endl;
    rsa_res << "CPU decryption: " << cd_mean << " µs" << endl;
    rsa_res << "CPU total: " << ck_mean + ce_mean + cd_mean << " µs" << endl;
    rsa_res << "GPU total: " << gpu_mean << " µs" << endl;

}

int main() {
    std::cout << "Timing RSA" << std::endl; 
    time_rsa();
    return 0;
}