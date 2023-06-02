#ifndef NEURALPY_WRAPPERFUNCTIONS_H
#define NEURALPY_WRAPPERFUNCTIONS_H

#include "WrapperClasses.h"
#include "NeuralOFHE/NeuralOFHE.h"


void InitializePythonEnvironment (PythonContext context, uint32_t batchSize, uint32_t initialChannels) {
    InitializeCryptoEnvironment(context.getContext(), batchSize, initialChannels);
}


#endif //NEURALPY_WRAPPERFUNCTIONS_H
