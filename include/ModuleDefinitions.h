#ifndef NEURALPY_MODULEDEFINITIONS_H
#define NEURALPY_MODULEDEFINITIONS_H


#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "NeuralOFHE/NeuralOFHE.h"

#include "../include/WrapperClasses.h"
#include "WrapperFunctions.h"

namespace py = pybind11;


template<typename T>
std::function<PythonCiphertext (T&, PythonCiphertext)> initForward() {
    return [](T& self, PythonCiphertext x) -> PythonCiphertext {
            Ciphertext<DCRTPoly> input = x.getCiphertext();
            PythonCiphertext result;

            result.setCiphertext(self.forward(input));

            return result;
    };
}


void defineEnums (py::module_& m) {
    py::enum_<SecurityLevel>(m, "SecurityLevel")
            .value("HEStd_NotSet", HEStd_NotSet)
            .value("HEStd_128_classic", HEStd_128_classic)
            .value("HEStd_192_classic", HEStd_192_classic)
            .value("HEStd_256_classic", HEStd_256_classic)
            .export_values();

    py::enum_<ScalingTechnique>(m, "ScalingTechnique")
            .value("FIXEDMANUAL", FIXEDMANUAL)
            .value("FIXEDAUTO", FIXEDAUTO)
            .value("FLEXIBLEAUTO", FLEXIBLEAUTO)
            .value("FLEXIBLEAUTOEXT", FLEXIBLEAUTOEXT)
            .value("NORESCALE", NORESCALE)
            .value("INVALID_RS_TECHNIQUE", INVALID_RS_TECHNIQUE)
            .export_values();

    py::enum_<SecretKeyDist>(m, "SecretKeyDist")
            .value("GAUSSIAN", GAUSSIAN)
            .value("UNIFORM_TERNARY", UNIFORM_TERNARY)
            .value("SPARSE_TERNARY", SPARSE_TERNARY)
            .export_values();

    py::enum_<PKESchemeFeature>(m, "PKESchemeFeature")
            .value("PKE", PKE)
            .value("KEYSWITCH", KEYSWITCH)
            .value("PRE", PRE)
            .value("LEVELEDSHE", LEVELEDSHE)
            .value("ADVANCEDSHE", ADVANCEDSHE)
            .value("MULTIPARTY", MULTIPARTY)
            .value("FHE", FHE)
            .export_values();

    py::enum_<KeySwitchTechnique>(m, "KeySwitchTechnique")
            .value("INVALID_KS_TECH", INVALID_KS_TECH)
            .value("BV", BV)
            .value("HYBRID", HYBRID)
            .export_values();
}


void defineBasicOpenFHEModules (py::module_& m) {
    py::class_<Parameters>(m, "Parameters")
            .def(py::init<>())
            .def("SetRingDim", &Parameters::SetRingDim, py::arg("ring_dim"))
            .def("SetScalingModSize", &Parameters::SetScalingModSize, py::arg("scal_size"))
            .def("SetFirstModSize", &Parameters::SetFirstModSize, py::arg("fist_size"))
            .def("SetMultiplicativeDepth", &Parameters::SetMultiplicativeDepth, py::arg("mult_depth"))
            .def("SetSecurityLevel", &Parameters::SetSecurityLevel, py::arg("security_level"))
            .def("SetBatchSize", &Parameters::SetBatchSize, py::arg("batch_size"))
            .def("SetScalingTechnique", &Params::SetScalingTechnique, py::arg("technique"))
            .def("SetSecretKeyDist", &Params::SetSecretKeyDist, py::arg("distribution"))
            .def("SetKeySwitchTechnique", &Params::SetKeySwitchTechnique, py::arg("technique"));

    py::class_<PythonKey<PublicKey<DCRTPoly>>>(m, "PublicKey")
            .def(py::init<>())
            .def("load", &PythonKey<PublicKey<DCRTPoly>>::load, py::arg("filePath"))
            .def("save", &PythonKey<PublicKey<DCRTPoly>>::save, py::arg("filePath"));
    py::class_<PythonKey<PrivateKey<DCRTPoly>>>(m, "PrivateKey")
            .def(py::init<>())
            .def("load", &PythonKey<PrivateKey<DCRTPoly>>::load, py::arg("filePath"))
            .def("save", &PythonKey<PrivateKey<DCRTPoly>>::save, py::arg("filePath"));

    py::class_<PythonKeypair>(m, "KeyPair")
            .def(py::init<>())
            .def_readwrite("publicKey", &PythonKeypair::publicKey)
            .def_readwrite("privateKey", &PythonKeypair::privateKey);

    py::class_<PythonCiphertext>(m, "Ciphertext")
            .def(py::init<>());

    py::class_<PythonPlaintext>(m, "Plaintext")
            .def(py::init<>())
            .def("GetPackedValue", &PythonPlaintext::GetPackedValue)
            .def("SetLength", &PythonPlaintext::SetLength, py::arg("length"));

    py::class_<PythonContext>(m, "Context")
            .def(py::init<>())
            .def("Enable", &PythonContext::Enable, py::arg("feature"))
            .def("KeyGen", &PythonContext::KeyGen)
            .def("GetRingDimension", &PythonContext::GetRingDim)
            .def("Encrypt", &PythonContext::Encrypt, py::arg("plaintext"), py::arg("publicKey"))
            .def("PackPlaintext", &PythonContext::PackPlaintext, py::arg("plaintext"))
            .def("Decrypt", &PythonContext::Decrypt, py::arg("ciphertext"), py::arg("privateKey"))
            .def("EvalMultKeyGen", &PythonContext::EvalMultKeyGen, py::arg("privateKey"))
            .def("GenRotateKeys", &PythonContext::GenRotations)
            .def("save", &PythonContext::save, py::arg("filePath"))
            .def("load", &PythonContext::load, py::arg("filePath"))
            .def("saveMultKeys", &PythonContext::saveMultKeys, py::arg("filePath"))
            .def("loadMultKeys", &PythonContext::loadMultKeys, py::arg("filePath"))
            .def("saveRotKeys", &PythonContext::saveRotKeys, py::arg("filePath"))
            .def("loadRotKeys", &PythonContext::loadRotKeys, py::arg("filePath"));
}


void defineNeuralOFHETypes (py::module_& m) {
    py::class_<Operator, PythonOperator>(m, "Operator")
            .def(py::init<uint32_t&, std::string>())
            .def("forward", &Operator::forward)
            .def("GetName", &Operator::getName);

    py::class_<nn::Conv2D, PyImpl<nn::Conv2D>, Operator>(m, "Conv2D")
            .def(py::init<matVec, std::vector<double>>())
            .def("__call__", initForward<nn::Conv2D>());

    py::class_<nn::Gemm, PyImpl<nn::Gemm>, Operator>(m, "Gemm")
            .def(py::init<matVec, std::vector<double>>())
            .def("__call__", initForward<nn::Gemm>());

    py::class_<nn::AveragePool, PyImpl<nn::AveragePool>, Operator>(m, "AveragePool")
            .def(py::init<matVec>())
            .def("__call__", initForward<nn::AveragePool>());

    py::class_<nn::BatchNorm, PyImpl<nn::BatchNorm>, Operator>(m, "BatchNorm")
            .def(py::init<std::vector<double>, std::vector<double>, double, double, double>(),
                    py::arg("weights"), py::arg("biases"), py::arg("var"), py::arg("mu"), py::arg("epsilon"))
            .def("__call__", initForward<nn::BatchNorm>());


    py::class_<ActivationFunction, PythonActivation, Operator>(m, "ActivationFunction")
            .def(py::init<double, double, uint32_t, uint32_t&, std::string>());

    py::class_<nn::ReLU, ActivationFunction>(m, "ReLU")
            .def(py::init<double, double, unsigned int>())
            .def("__call__", initForward<nn::ReLU>());

    py::class_<nn::Swish, ActivationFunction>(m, "Swish")
            .def(py::init<double, double, unsigned int>())
            .def("__call__", initForward<nn::Swish>());

    py::class_<nn::Sigmoid, ActivationFunction>(m, "Sigmoid")
            .def(py::init<double, double, unsigned int>())
            .def("__call__", initForward<nn::Sigmoid>());

}


#endif //NEURALPY_MODULEDEFINITIONS_H
