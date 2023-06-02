#ifndef NEURALPY_WRAPPERCLASSES_H
#define NEURALPY_WRAPPERCLASSES_H

typedef CCParams<CryptoContextCKKSRNS> Parameters;
typedef Ciphertext<DCRTPoly> Cipher;
typedef CryptoContext<DCRTPoly> Context;

class PythonContext {
public:
    PythonContext (Parameters params) {
        context = GenCryptoContext(params);
    }

    void Enable(PKESchemeFeature feature) {
        context->Enable(feature);
    }

    uint32_t GetRingDim() {
        return context->GetRingDimension();
    }

    Context getContext() {
        return context;
    }

private:
    Context context;
};


#endif //NEURALPY_WRAPPERCLASSES_H
