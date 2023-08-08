/**
 * @file WrapperClasses.h
 *
 * @brief This file includes definitions of classes wrapped around the plane OpenFHE and NeuralOFHE classes because there were
 * issues caused by long template arguments and typedefs which where assigned to shared pointers. Each class requires a
 * getter and setter method for setting and getting the shared pointer to the underlying OpenFHE object. The plain
 * OpenFHE will not be directly accessed by the Python front end. Furthermore there will only be an empty constructor
 * that does nothing. The interactions between the classes will be handled by C++ and not within the Python application
 *
 * @author Linus Henke
 * Contact: linus.henke@mci.edu
 *
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

/***
 * Class used to represent Private and Public keys in Python.
 *
 * @tparam T Should be either set to PrivateKey<DCRTPoly> or PublicKey<DCRTPoly>
 */
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


/***
 * Class to represent a keypair in Python. Similar to OpenFHE the publicKey and privateKey can be read and written to
 * from outside the class.
 */
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
    }

    Plaintext getPlaintext() {
        return pl;
    }

    /***
     * Setting the size of the plaintext vector.
     *
     * @param length
     */
    void SetLength (uint32_t length) {
        pl->SetLength(length);
    }

    /***
     * Getting the plaintext value as a C++ iterator. Conversion between C++ iterators and Python iterators is seamless
     * with Pybind11.
     *
     * @return Plain vector
     */
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

    /***
     * Method that allows a ciphertexts to be serialized from a file.
     *
     * @param filePath Path to Ciphertext file
     */
    void load(std::string filePath) {
        if (!Serial::DeserializeFromFile(filePath, ciphertext, SerType::BINARY)) {
            std::cerr << "Could not deserialize " + filePath + " ciphertext" << std::endl;
            exit(1);
        }
        std::cout << "Ciphertext " + filePath << " deserialized." << std::endl;
    }

    /***
     * Method that allows serialization of a ciphertext.
     *
     * @param filePath
     */
    void save(std::string filePath) {
        if(!Serial::SerializeToFile(filePath, ciphertext, SerType::BINARY)) {
            std::cerr << "Error Serializing ciphertext." << std::endl;
            exit(1);
        }
        std::cout << "Ciphertext serialized." << std::endl;
    }

    /***
     * Method to set the slots of the ciphertext.
     *
     * @param slots Number of slots the ciphertext is supposed to have.
     */
    void setSlots(uint32_t slots) {
        ciphertext->SetSlots(slots);
    }

    /***
     * Getter Method for the number of slots in the Ciphertext
     *
     * @return Number of slots
     */
    uint32_t getSlots() {
        return ciphertext->GetSlots();
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
        Ciphertext<DCRTPoly> ciph_result = context->EvalAdd(a.getCiphertext(), b.getCiphertext());
        result.setCiphertext(ciph_result);

        return result;
    }

    PythonCiphertext EvalAdd (std::vector<double> a, PythonCiphertext b) {
        PythonCiphertext result;
        Plaintext pl = context->MakeCKKSPackedPlaintext(a);
        Ciphertext<DCRTPoly> ciph_result = context->EvalAdd(pl, b.getCiphertext());
        result.setCiphertext(ciph_result);

        return result;
    }

    PythonCiphertext EvalSub (PythonCiphertext a, PythonCiphertext b) {
        PythonCiphertext result;
        Ciphertext<DCRTPoly> ciph_result = context->EvalSub(a.getCiphertext(), b.getCiphertext());
        result.setCiphertext(ciph_result);

        return result;
    }

    PythonCiphertext EvalSub (std::vector<double> a, PythonCiphertext b, bool reverse=false) {
        PythonCiphertext result;
        Plaintext pl = context->MakeCKKSPackedPlaintext(a);
        Ciphertext<DCRTPoly> ciph_result;
        if (!reverse) {
            ciph_result = context->EvalSub(pl, b.getCiphertext());
        }else {
            ciph_result = context->EvalSub(b.getCiphertext(), pl);
        }
        result.setCiphertext(ciph_result);

        return result;
    }

    PythonCiphertext EvalMult (PythonCiphertext a, PythonCiphertext b) {
        PythonCiphertext result;
        Ciphertext<DCRTPoly> ciph_result = context->EvalMult(a.getCiphertext(), b.getCiphertext());
        result.setCiphertext(ciph_result);

        return result;
    }

    PythonCiphertext EvalMult (std::vector<double> a, PythonCiphertext b) {
        PythonCiphertext result;
        Plaintext pl = context->MakeCKKSPackedPlaintext(a);
        Ciphertext<DCRTPoly> ciph_result = context->EvalMult(pl, b.getCiphertext());
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

/***
 * Trampoline class for the Operator base class so that Pybind11 can handle virtual functions.
 */
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

/***
 * Template class that overrides the forward method for the inherited class in the template class.
 *
 * @tparam Impl Inherited class
 */
template <class Impl> class PyImpl : public Impl {
public:
    using Impl::Impl;

    Ciphertext<DCRTPoly> forward (Ciphertext<DCRTPoly> x) override {
        PYBIND11_OVERRIDE(Ciphertext<DCRTPoly>, Impl, forward, x);
    }
};

/***
 * Implementation of the activation function class that overrides the forward function. There is no requirement to
 * create a trampoline for the getFunc method since this is a protected method.
 */
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
