/**
 * This file includes definitions of classes wrapped around the plane OpenFHE and NeuralOFHE classes because there were
 * issues caused by long template arguments and typedefs which where assigned to shared pointers. Each class requires a
 * getter and setter method for setting and getting the shared pointer to the underlying OpenFHE object. The plain
 * OpenFHE will not be directly accessed by the Python front end. Furthermore there will only be an empty constructor
 * that does nothing. The interactions between the classes will be handled by C++ and not within the Python application
 *
 * @author Linus Henke
 * @
 */
#ifndef NEURALPY_WRAPPERCLASSES_H
#define NEURALPY_WRAPPERCLASSES_H

#include "openfhe.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "cryptocontext-ser.h"

typedef CCParams<CryptoContextCKKSRNS> Parameters;
typedef Ciphertext<DCRTPoly> Cipher;
typedef CryptoContext<DCRTPoly> Context;

template<class T>
class PythonKey {
public:
    PythonKey() {}

    void setKey(T k) {
        this->key = k;
    }

    T getKey() {
        return key;
    }

    void load(std::string filePath) {
        if (!Serial::DeserializeFromFile(filePath, key, SerType::BINARY)) {
            std::cerr << "Error deserializing key from " << filePath << "." << std::endl;
            exit(1);
        }

        std::cout << "Key deserialized from " << filePath << "." << std::endl;
    }

    void save(std::string filePath) {
        if (!Serial::SerializeToFile(filePath, key, SerType::BINARY)) {
            std::cerr << "Error serializing key to " << filePath << "." << std::endl;
            std::exit(1);
        }
        std::cout << "Key serialized to " << filePath << "." << std::endl;
    }

private:
    T key;
};


class PythonKeypair {
public:
    PythonKeypair () {}

    PythonKey<PublicKey<DCRTPoly>> publicKey;

    PythonKey<PrivateKey<DCRTPoly>> privateKey;

private:
    KeyPair<DCRTPoly> keys;
};


class PythonPlaintext {
public:
    PythonPlaintext () {}

    void setPlaintext(Plaintext plain) {
        this->pl = plain;
    };

    Plaintext getPlaintext() {
        return pl;
    }

    void SetLength (uint32_t length) {
        pl->SetLength(length);
    }

    std::vector<double> GetPackedValue () {
        return pl->GetRealPackedValue();
    }

private:
    Plaintext pl;
};


class PythonCiphertext {
public:
    PythonCiphertext () {}

    void setCiphertext(Cipher cipher) {
        ciphertext = cipher;
    }

    Cipher getCiphertext () {
        return ciphertext;
    }

    void load(std::string filePath) {
        if (!Serial::DeserializeFromFile(filePath, ciphertext, SerType::BINARY)) {
            std::cerr << "Could not deserialize " + filePath + " ciphertext" << std::endl;
            exit(1);
        }
        std::cout << "Ciphertext " + filePath << " deserialized." << std::endl;
    }

    void save(std::string filePath) {
        if(!Serial::SerializeToFile(filePath, ciphertext, SerType::BINARY)) {
            std::cerr << "Error Serializing ciphertext." << std::endl;
            exit(1);
        }
        std::cout << "Ciphertext serialized." << std::endl;
    }

private:
    Cipher ciphertext;
};


class PythonContext {
public:
    PythonContext () {}

    void SetContext(Context cont) {
        this->context = cont;
    }

    void Enable(PKESchemeFeature feature) {
        context->Enable(feature);
    }

    void EvalMultKeyGen (PythonKey<PrivateKey<DCRTPoly>> privateKey) {
        context->EvalMultKeyGen(privateKey.getKey());
    }

    void GenRotations (PythonKey<PrivateKey<DCRTPoly>> key) {
        std::vector<int> rotations = GetRotations(context->GetEncodingParams()->GetBatchSize());
        context->EvalRotateKeyGen(key.getKey(), rotations);
    }

    uint32_t GetRingDim() {
        return context->GetRingDimension();
    }

    PythonCiphertext Encrypt(PythonPlaintext plaintext, PythonKey<PublicKey<DCRTPoly>> publicKey) {
        PythonCiphertext result;
        result.setCiphertext(context->Encrypt(publicKey.getKey(), plaintext.getPlaintext()));
        return result;
    }

    PythonPlaintext Decrypt(PythonCiphertext cipher, PythonKey<PrivateKey<DCRTPoly>> privateKey) {
        PythonPlaintext result;
        Plaintext pl;
        context->Decrypt(privateKey.getKey(), cipher.getCiphertext(), &pl);

        result.setPlaintext(pl);

        return result;
    }

    PythonPlaintext PackPlaintext(std::vector<double> plaintext) {
        PythonPlaintext result;
        result.setPlaintext(context->MakeCKKSPackedPlaintext(plaintext));
        return result;
    }

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

    void load(std::string filePath) {
        if (!Serial::DeserializeFromFile(filePath, context, SerType::BINARY)) {
            std::cerr << "Error loading context" << std::endl;
            exit(1);
        }
        std::cout << "Context has been loaded." << std::endl;
    }

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

    void save(std::string filePath) {
        if (!Serial::SerializeToFile(filePath, context, SerType::BINARY)) {
            std::cerr << "Error serializing context." << std::endl;
            exit(1);
        }
        std::cout << "Cryptocontext serialized!" << std::endl;
    }

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


class PythonOperator : public Operator {
public:
    using Operator::Operator;

    Ciphertext<DCRTPoly> forward (Ciphertext<DCRTPoly> x) override {
        PYBIND11_OVERRIDE_PURE(
                Ciphertext<DCRTPoly>,
                Operator,
                forward,
                x
                );
    }
};


template <class Impl> class PyImpl : public Impl {
public:
    using Impl::Impl;

    Ciphertext<DCRTPoly> forward (Ciphertext<DCRTPoly> x) override {
        PYBIND11_OVERRIDE(Ciphertext<DCRTPoly>, Impl, forward, x);
    }
};


class PythonActivation : public ActivationFunction {
public:
    using ActivationFunction::ActivationFunction;

    Ciphertext<DCRTPoly> forward (Ciphertext<DCRTPoly> x) override {
        PYBIND11_OVERRIDE(
                Ciphertext<DCRTPoly>,
                ActivationFunction,
                forward,
                x
        );
    }

    const std::function<double (double)> &getFunc() override {
        PYBIND11_OVERRIDE_PURE(
                std::function<double (double)>,
                ActivationFunction,
                getFunc
        );
    }
};

#endif //NEURALPY_WRAPPERCLASSES_H
