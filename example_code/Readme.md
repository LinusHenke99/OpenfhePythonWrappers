# Example Code
This directory includes Python example code in order to show how the library should be used once it is installed. The 
`keygen.py` and `cryptonet.py` scripts are both used for creating encrypted inference on the 
[MNIST](http://yann.lecun.com/exdb/mnist/) dataset using the cryptonets neural network. The weights and biases of the 
model are stored as `.npy` files in the `model` folder, and can be loaded by the library later. The `images` folder 
includes some example 32x32 files of the MNIST dataset, on which encrypted inference can be made.

## Key Generation
Before the inference can be made, all necessary keys need to be generated. This is done by running the `keygen.py` 
script, which will store the needed keys in the `keys` directory, which should be created by CMake. The script will 
generate the following keys
- A private key for decrypting encrypted ciphertexts
- A public key for encrypting plaintexts
- Multiplication keys for carrying out multiplications on the cipherspace
- Rotation keys for rotating given ciphertexts

The script will also serialize a context object which is vital for doing any FHE operations using OpenFHE.

## Inference
Encrypted inference is done by the `cryptonet_inference.py` script. This will load the generated keys, pick a random 
image from the dataset and encrypt it, and then make inference on that using the provided model.