#ifndef NEURALPY_WRAPPERFUNCTIONS_H
#define NEURALPY_WRAPPERFUNCTIONS_H

#include "WrapperClasses.h"
#include "NeuralOFHE/NeuralOFHE.h"


void SetPythonContext (PythonContext context) {
    SetContext(context.getContext());
}


PythonContext MakeContext(Parameters params) {
    auto context = GenCryptoContext(params);

    PythonContext result;
    result.SetContext(context);

    return result;
}


#endif //NEURALPY_WRAPPERFUNCTIONS_H
