#ifndef NEURALPY_WRAPPERCLASSES_H
#define NEURALPY_WRAPPERCLASSES_H

typedef CCParams<CryptoContextCKKSRNS> Parameters;
typedef Ciphertext<DCRTPoly> Cipher;
typedef CryptoContext<DCRTPoly> Context;

template<typename T>
class PythonKey {
public:
    PythonKey() {};

    void setKey(T k) {
        this->key = k;
    }

    T getKey() {
        return key;
    }

private:
    T key;
};


class PythonPlaintext {
public:
    PythonPlaintext () {};

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
    PythonCiphertext () {};

    void setCiphertext(Cipher cipher) {
        ciphertext = cipher;
    }

    Cipher getCiphertext () {
        return ciphertext;
    }

private:
    Cipher ciphertext;
};


class PythonContext {
public:
    PythonContext (Parameters params) {
        context = GenCryptoContext(params);
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

    Context getContext() {
        return context;
    }

private:
    Context context;
};


class PythonKeypair {
public:
    PythonKeypair (PythonContext context) {
        keys = context.getContext()->KeyGen();

        publicKey.setKey(keys.publicKey);

        privateKey.setKey(keys.secretKey);
    }

    PythonKey<PublicKey<DCRTPoly>> publicKey;

    PythonKey<PrivateKey<DCRTPoly>> privateKey;

private:
    KeyPair<DCRTPoly> keys;
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
