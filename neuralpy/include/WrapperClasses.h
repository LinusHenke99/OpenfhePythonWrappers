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
typedef CryptoContext<DCRTPoly> Context;

#include "PythonCiphertext.h"
#include "PythonContext.h"
#include "PythonKeys.h"

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
