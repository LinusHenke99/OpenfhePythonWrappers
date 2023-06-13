#ifndef NEURALPY_WRAPPERFUNCTIONS_H
#define NEURALPY_WRAPPERFUNCTIONS_H

#include "WrapperClasses.h"
#include "NeuralOFHE/NeuralOFHE.h"


void InitializePythonEnvironment (PythonContext context) {
    InitializeCryptoEnvironment(context.getContext());
}


#endif //NEURALPY_WRAPPERFUNCTIONS_H
