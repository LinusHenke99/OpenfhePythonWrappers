//
// Created by lchenke on 10.08.23.
//

#ifndef NEURALPY_PYTHONCONTEXT_H
#define NEURALPY_PYTHONCONTEXT_H

#include "OpenFHEPrerequisites.h"

#include "PythonCiphertext.h"
#include "PythonKeys.h"


class PythonContext {
public:
    PythonContext () {}

    void SetContext(Context cont) {
        this->context = cont;
    }

    void Enable(PKESchemeFeature feature) {
        context->Enable(feature);
    }

    /***
     * Method that generates multiplication keys within the context object.
     *
     * @param privateKey Mult. keys are generated from the private key
     */
    void EvalMultKeyGen (PythonKey<PrivateKey<DCRTPoly>> privateKey) {
        context->EvalMultKeyGen(privateKey.getKey());
    }

    PythonCiphertext EvalAdd (PythonCiphertext a, PythonCiphertext b) {
        PythonCiphertext result;
        Cipher ciph_result = context->EvalAdd(a.getCiphertext(), b.getCiphertext());
        result.setCiphertext(ciph_result);

        return result;
    }

    PythonCiphertext EvalAdd (std::vector<double> a, PythonCiphertext b) {
        PythonCiphertext result;
        Plaintext pl = context->MakeCKKSPackedPlaintext(a);
        Cipher ciph_result = context->EvalAdd(pl, b.getCiphertext());
        result.setCiphertext(ciph_result);

        return result;
    }

    PythonCiphertext EvalAdd (double a, PythonCiphertext b) {
        PythonCiphertext result;
        Cipher ciph_result = context->EvalAdd(a, b.getCiphertext());
        result.setCiphertext(ciph_result);

        return result;
    }

    PythonCiphertext EvalSub (PythonCiphertext a, PythonCiphertext b) {
        PythonCiphertext result;
        Cipher ciph_result = context->EvalSub(a.getCiphertext(), b.getCiphertext());
        result.setCiphertext(ciph_result);

        return result;
    }

    PythonCiphertext EvalSub (std::vector<double> a, PythonCiphertext b, bool reverse=false) {
        PythonCiphertext result;
        Plaintext pl = context->MakeCKKSPackedPlaintext(a);
        Cipher ciph_result;
        if (!reverse) {
            ciph_result = context->EvalSub(pl, b.getCiphertext());
        }else {
            ciph_result = context->EvalSub(b.getCiphertext(), pl);
        }
        result.setCiphertext(ciph_result);

        return result;
    }

    PythonCiphertext EvalSub (double a, PythonCiphertext b, bool reverse=false) {
        PythonCiphertext result;
        Cipher ciph_result;
        if (!reverse) {
            ciph_result = context->EvalSub(a, b.getCiphertext());
        }else {
            ciph_result = context->EvalSub(b.getCiphertext(), a);
        }
        result.setCiphertext(ciph_result);

        return result;
    }

    /***
     * Overload of ciphertext ciphertext multiplication
     *
     * @param a
     * @param b
     * @return
     */
    PythonCiphertext EvalMult (PythonCiphertext a, PythonCiphertext b) {
        PythonCiphertext result;
        Cipher ciph_result = context->EvalMult(a.getCiphertext(), b.getCiphertext());
        result.setCiphertext(ciph_result);

        return result;
    }

    /***
     * Overload of plaintext ciphertext multiplication
     *
     * @param a
     * @param b
     * @return
     */
    PythonCiphertext EvalMult (std::vector<double> a, PythonCiphertext b) {
        PythonCiphertext result;
        Plaintext pl = context->MakeCKKSPackedPlaintext(a);
        Cipher ciph_result = context->EvalMult(pl, b.getCiphertext());
        result.setCiphertext(ciph_result);

        return result;
    }

    /***
     * Overload of double, ciphertext multiplication
     *
     * @param a
     * @param b
     * @return
     */
    PythonCiphertext EvalMult (double a, PythonCiphertext b) {
        PythonCiphertext result;
        Cipher ciph_result = context->EvalMult(a, b.getCiphertext());
        result.setCiphertext(ciph_result);

        return result;
    }

    /***
     * Generate rotation keys required to do matrix multiplication with the contexts batch size.
     *
     * @param key
     */
    void GenRotations (PythonKey<PrivateKey<DCRTPoly>> key) {
        std::vector<int> rotations = GetRotations(context->GetEncodingParams()->GetBatchSize());
        context->EvalRotateKeyGen(key.getKey(), rotations);
    }

    /***
     * Get dimension of the polynomial ring within the context.
     *
     * @return Ring dimension
     */
    uint32_t GetRingDim() {
        return context->GetRingDimension();
    }

    /***
     * Encrypt a plaintext using the public key.
     *
     * @param plaintext Plaintext that should be encrypted.
     * @param publicKey Public key of the application.
     * @return Encrypted ciphertext.
     */
    PythonCiphertext Encrypt(PythonPlaintext plaintext, PythonKey<PublicKey<DCRTPoly>> publicKey) {
        PythonCiphertext result;
        result.setCiphertext(context->Encrypt(publicKey.getKey(), plaintext.getPlaintext()));
        return result;
    }

    /***
     * Decrypt a ciphertext using the private key.
     *
     * @param cipher Ciphertext that should be decrypted.
     * @param privateKey Private key of the application.
     * @return Plaintext object resulting from the encryption.
     */
    PythonPlaintext Decrypt(PythonCiphertext cipher, PythonKey<PrivateKey<DCRTPoly>> privateKey) {
        PythonPlaintext result;
        Plaintext pl;

        uint32_t power = 1;
        while (power <= cipher.getSlots())
            power *= 2;

        //  Needs to be set to the next largest power of two, otherwise it won't decrypt
        cipher.setSlots(power);
        context->Decrypt(privateKey.getKey(), cipher.getCiphertext(), &pl);

        result.setPlaintext(pl);

        return result;
    }

    /***
     * Packing a C++ iterator containing doubles into a plaintext object.
     *
     * @param plaintext Plaintext in form of a C++ iterator
     * @return Plaintext object
     */
    PythonPlaintext PackPlaintext(std::vector<double> plaintext) {
        PythonPlaintext result;
        result.setPlaintext(context->MakeCKKSPackedPlaintext(plaintext));
        return result;
    }

    /***
     * Generate keypair for public key encryption.
     *
     * @return Keypair object
     */
    PythonKeypair KeyGen () {
        PythonKeypair keys;
        auto keyPair = context->KeyGen();

        keys.privateKey.setKey(keyPair.secretKey);
        keys.publicKey.setKey(keyPair.publicKey);

        return keys;
    }

    Context getContext() {
        return context;
    }

    /***
     * Load context object from file.
     *
     * @param filePath
     */
    void load(std::string filePath) {
        if (!Serial::DeserializeFromFile(filePath, context, SerType::BINARY)) {
            std::cerr << "Error loading context" << std::endl;
            exit(1);
        }
        std::cout << "Context has been loaded." << std::endl;
    }

    /***
     * Load multiplication keys from file into the context object.
     *
     * @param filePath
     */
    void loadMultKeys(std::string filePath) {
        context->ClearEvalMultKeys();

        std::ifstream multKeyIStream(filePath, std::ios::in | std::ios::binary);
        if (!multKeyIStream.is_open()) {
            std::cerr << "Error opening mult. key file." << std::endl;
            exit(1);
        }
        if (!context->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY)) {
            std::cerr << "Error loading mult. key." << std::endl;
            exit(1);
        }
        std::cout << "Deserialized mult. key" << std::endl;
        multKeyIStream.close();
    }

    /***
     * Load rotation keys from file into the context object.
     *
     * @param filePath
     */
    void loadRotKeys (std::string filePath) {
        context->ClearEvalAutomorphismKeys();

        std::ifstream rotKeyIStream(filePath, std::ios::in | std::ios::binary);
        if (!rotKeyIStream.is_open()) {
            std::cerr << "Error opening rot. key file." << std::endl;
            exit(1);
        }
        if (!context->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY)) {
            std::cerr << "Error loading rot. key." << std::endl;
            exit(1);
        }
        std::cout << "Deserialized rot. key" << std::endl;
        rotKeyIStream.close();
    }

    /***
     * Serialize context object without keys to file.
     *
     * @param filePath
     */
    void save(std::string filePath) {
        if (!Serial::SerializeToFile(filePath, context, SerType::BINARY)) {
            std::cerr << "Error serializing context." << std::endl;
            exit(1);
        }
        std::cout << "Cryptocontext serialized!" << std::endl;
    }

    /***
     * Serialize multiplication keys to file.
     *
     * @param filePath
     */
    void saveMultKeys(std::string filePath) {
        std::ofstream multKeyFile(filePath, std::ios::out | std::ios::binary);
        if (multKeyFile.is_open()) {
            if (!context->SerializeEvalMultKey(multKeyFile, SerType::BINARY)) {
                std::cerr << "Error serializing multiplication key." << std::endl;
                std::exit(1);
            }
            std::cout << "Multiplication key serialized!" << std::endl;
            multKeyFile.close();

        } else {
            std::cerr << "Error opening Mult Key file..." << std::endl;
        }
    }

    /***
     * Serialize rotation keys to file.
     *
     * @param filePath
     */
    void saveRotKeys(std::string filePath) {
        std::ofstream rotKeyFile(filePath, std::ios::out | std::ios::binary);
        if (rotKeyFile.is_open()) {
            if (!context->SerializeEvalAutomorphismKey(rotKeyFile, SerType::BINARY)) {
                std::cerr << "Error serializing rotation key." << std::endl;
                std::exit(1);
            }
            std::cout << "Rotation key serialized!" << std::endl;
            rotKeyFile.close();
        } else {
            std::cerr << "Error opening Mult Key file..." << std::endl;
        }
    }

private:
    Context context;
};

#endif //NEURALPY_PYTHONCONTEXT_H
