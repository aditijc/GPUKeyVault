#include "rsa.h"
#include<iostream>
#include<math.h>
#include<string.h>
#include<stdlib.h>
#include <openssl/pem.h>
 
using namespace std;
 
long int p, q, n, t, flag, e[100], d[100], temp[100], j, m[100], en[100], i;
char msg[100];
int prime(long int);
void ce();
long int cd(long int);
void encrypt();
void decrypt();

int prime(long int pr)
{
    int i;
    j = sqrt(pr);
    for (i = 2; i <= j; i++)
    {
        if (pr % i == 0)
            return 0;
    }
    return 1;
}

void saveKeysToPEM(const char *pubKey, const char *privKey, const std::string& pubFilePath, const std::string& privFilePath) {
    
    FILE* pubFile = fopen(pubFilePath.c_str(), "w");
    if (!pubFile) {
        std::cerr << "Error opening public file for writing." << std::endl;
        return;
    }
    FILE* privFile = fopen(privFilePath.c_str(), "w");
    if (!privFile) {
        std::cerr << "Error opening private file for writing." << std::endl;
        return;
    }

    fputs("-----BEGIN PUBLIC KEY-----\n", pubFile);
    if (fputs(pubKey, pubFile) == EOF) {
        std::cerr << "Error writing data to PEM file." << std::endl;
    }
    fputs("\n-----END PUBLIC KEY-----", pubFile);

    fputs("-----BEGIN PRIVATE KEY-----\n", privFile);
    if (fputs(privKey, privFile) == EOF) {
        std::cerr << "Error writing data to PEM file." << std::endl;
    }
    fputs("\n-----END PRIVATE KEY-----", privFile);

    // Close the PEM file
    fclose(pubFile);
    fclose(privFile);
}

int main()
{
    cout << "\nEnter the first prime number:\n";
    cin >> p;
    flag = prime(p);
    if (flag == 0)
    {
        cout << "\nWRONG INPUT\n";
        exit(1);
    }
    cout << "\nEnter the second prime number:\n";
    cin >> q;
    flag = prime(q);
    if (flag == 0 || p == q)
    {
        cout << "\nWRONG INPUT\n";
        exit(1);
    }
    cout << "\nEnter the message to encrypt:\n";
    fflush(stdin);
    cin >> msg;
    for (i = 0; msg[i] != '\0'; i++)
        m[i] = msg[i];
    n = p * q;
    t = (p - 1) * (q - 1);
    ce();
    cout << "\nThe public key and the private key are:\n";
    for (i = 0; i < 1; i++)
        cout << e[i] << "\t" << d[i] << "\n";
    saveKeysToPEM(std::to_string(e[i]).c_str(), std::to_string(d[i]).c_str(), "public-keys/rsa_private_demo.pem", "private-keys/rsa_private_demo.pem");
    encrypt();
    decrypt();
    return 0;
}
void ce()
{
    int k;
    k = 0;
    for (i = 2; i < t; i++)
    {
        if (t % i == 0)
            continue;
        flag = prime(i);
        if (flag == 1 && i != p && i != q)
        {
            e[k] = i;
            flag = cd(e[k]);
            if (flag > 0)
            {
                d[k] = flag;
                k++;
            }
            if (k == 99)
                break;
        }
    }
}
long int cd(long int x)
{
    long int k = 1;
    while (1)
    {
        k = k + t;
        if (k % x == 0)
            return (k / x);
    }
}
void encrypt()
{
    long int pt, ct, key = e[0], k, len;
    i = 0;
    len = strlen(msg);
    while (i != len)
    {
        pt = m[i];
        pt = pt - 96;
        k = 1;
        for (j = 0; j < key; j++)
        {
            k = k * pt;
            k = k % n;
        }
        temp[i] = k;
        ct = k + 96;
        en[i] = ct;
        i++;
    }
    en[i] = -1;
    cout << "\nThe encrypted message is: \n";
    for (i = 0; en[i] != -1; i++)
        printf("%ld", en[i]);
}
void decrypt()
{
    long int pt, ct, key = d[0], k;
    i = 0;
    while (en[i] != -1)
    {
        ct = temp[i];
        k = 1;
        for (j = 0; j < key; j++)
        {
            k = k * ct;
            k = k % n;
        }
        pt = k + 96;
        m[i] = pt;
        i++;
    }
    m[i] = -1;
    cout << "\nThe decrypted message is:\n";
    std::string out = "";
    for (i = 0; m[i] != -1; i++)
        out += (char) m[i];
    printf("%s\n", out.c_str());
}
