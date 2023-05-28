# GPUKeyVault

An implementation of PGP software using the GPU. Developed by Aditi Chandrashekar, Saumya Chauhan, and Jake Goldman for Caltech's CS 179: GPU Programming course. GPUKeyVault uses RSA and ECDH algorithms with both CPU and GPU technologies for encryption, decryption, and key generation. 

## Build Instructions ##

Install the necessary dependencies for GPUKeyVault, including OpenSSL. 

`make install`

## Usage Instructions ##

Compile the necessary binaries to build the GPUKeyVault application.

`make build`

This generates a bianry executable `bin/main` containing the GPUKeyVault application. Running this application with no options will display the help menu, which can also be displayed with the `-h` flag. The general format of execution follows as: 

`bin/main [encryption mode] [-c|-g] [-e FILE|-d FILE|-n] [PUB-KEY] [PRIV-KEY]`
