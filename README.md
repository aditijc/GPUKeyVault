# GPUKeyVault

An implementation of PGP software using the GPU. Developed by Aditi Chandrashekar, Saumya Chauhan, and Jake Goldman for Caltech's CS 179: GPU Programming course. GPUKeyVault uses RSA and ECDH algorithms with both CPU and GPU technologies for encryption, decryption, and key generation. 

## Build Instructions ##

Install the necessary dependencies for GPUKeyVault, including OpenSSL. 

`make install`

## Usage Instructions ##

Compile the necessary binaries to build the GPUKeyVault application.

`make build`

This generates a bianry executable `bin/main` containing the GPUKeyVault application. Running this application with no options will display the help menu, which can also be displayed with the `-h` flag. The general format of execution follows as: 

### CPU ###

`bin/main [encryption mode] [-c] [-e FILE|-d FILE|-n] [PUB-KEY] [PRIV-KEY]`

### GPU ###

`bin/main [encryption mode] [-g] [FILE]`

## Examples ## 

### CPU Process ###

A basic usage example could include generating an ECDH key pair on the CPU, then using the pair encrypt and decrypt text. To generate the pairs:

`bin/main ecdh -c -n pub.pem priv.pem`

This generates a public key (public-keys/pub.pem) and private key (private-keys/priv.pem). Our sample directory contains a simple hello.txt for testing encryption and decryption. With our newly generated keys, to encrypt the hello.txt file:

`bin/main ecdh -c -e sample/hello.txt pub.pem priv.pem`

This generates encrypted text that is passed into stdout. This feature will be adapted to pass the output into a message file in the standard PGP form. Assuming this output text is stored in the encrypted file, we can decrypt it using 

`bin/main ecdh -c -d encrypted pub.pem priv.pem`

For further examples of usage, the `make test` target will execute predefined test cases for ECDH and RSA encryption on the CPU. The testing suite is located in the test/tester.cpp file. 

### GPU Process ###

Key generation to local storage proved to be a challenge due to existing key generation libaries not being fit for the GPU. So, our GPU PGP model completes the encryption and decryption in a single execution session. For example, the GPU RSA implementation can be run as follows:

`bin/main rsa -g sample/novel.txt`

## Screenshots ##

### Sample Encryption ###
![Output on encryption of 'hello world'](imgs/encrypted_out.png)

### Successful Testing Output ###
![Output on a succesfull run of testing](imgs/testing_out.png)