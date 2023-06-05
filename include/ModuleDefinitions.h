//
// Created by lchenke on 05.06.23.
//

#ifndef NEURALPY_MODULEDEFINITIONS_H
#define NEURALPY_MODULEDEFINITIONS_H


#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "NeuralOFHE/NeuralOFHE.h"

#include "../include/WrapperClasses.h"

namespace py = pybind11;


void defineBasicOpenFHEModules (py::module_& m) {
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

    py::enum_<KeySwitchTechnique>(m, "KeySwitchTechnique")
            .value("INVALID_KS_TECH", INVALID_KS_TECH)
            .value("BV", BV)
            .value("HYBRID", HYBRID)
            .export_values();

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
            .def(py::init<>());
    py::class_<PythonKey<PrivateKey<DCRTPoly>>>(m, "PrivateKey")
            .def(py::init<>());

    py::class_<PythonKeypair>(m, "KeyPair")
            .def(py::init<PythonContext>())
            .def_readonly("publicKey", &PythonKeypair::publicKey)
            .def_readonly("privateKey", &PythonKeypair::privateKey);


    py::class_<PythonCiphertext>(m, "Ciphertext")
            .def(py::init<>());

    py::class_<PythonPlaintext>(m, "Plaintext")
            .def(py::init<>())
            .def("GetPackedValue", &PythonPlaintext::GetPackedValue);


    py::enum_<PKESchemeFeature>(m, "PKESchemeFeature")
            .value("PKE", PKE)
            .value("KEYSWITCH", KEYSWITCH)
            .value("PRE", PRE)
            .value("LEVELEDSHE", LEVELEDSHE)
            .value("ADVANCEDSHE", ADVANCEDSHE)
            .value("MULTIPARTY", MULTIPARTY)
            .value("FHE", FHE)
            .export_values();

    py::class_<PythonContext>(m, "Context")
            .def(py::init<Parameters>(), py::arg("parameters"))
            .def("Enable", &PythonContext::Enable, py::arg("feature"))
            .def("GetRingDimension", &PythonContext::GetRingDim)
            .def("Encrypt", &PythonContext::Encrypt, py::arg("plaintext"), py::arg("publicKey"))
            .def("PackPlaintext", &PythonContext::PackPlaintext, py::arg("plaintext"))
            .def("Decrypt", &PythonContext::Decrypt, py::arg("ciphertext"), py::arg("privateKey"))
            .def("EvalMultKeyGen", &PythonContext::EvalMultKeyGen, py::arg("privateKey"));
}


void defineNeuralOFHETypes (py::module_& m) {
}


#endif //NEURALPY_MODULEDEFINITIONS_H
