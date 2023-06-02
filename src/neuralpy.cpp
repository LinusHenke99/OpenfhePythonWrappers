#include <pybind11/pybind11.h>
#include "NeuralOFHE/NeuralOFHE.h"

#include "../include/WrapperClasses.h"
#include "../include/WrapperFunctions.h"


namespace py = pybind11;


PYBIND11_MODULE(neuralpy, m) {
    py::enum_<SecurityLevel>(m, "SecurityLevel")
            .value("HEStd_NotSet", HEStd_NotSet)
            .value("HEStd_128_classic", HEStd_128_classic)
            .value("HEStd_192_classic", HEStd_192_classic)
            .value("HEStd_256_classic", HEStd_256_classic)
            .export_values();

    py::class_<Parameters>(m, "Parameters")
            .def(py::init<>())
            .def("SetRingDim", &Parameters::SetRingDim, py::arg("ring_dim"))
            .def("SetScalingModSize", &Parameters::SetScalingModSize, py::arg("scal_size"))
            .def("SetFirstModSize", &Parameters::SetFirstModSize, py::arg("fist_size"))
            .def("SetMultiplicativeDepth", &Parameters::SetMultiplicativeDepth, py::arg("mult_depth"))
            .def("SetSecurityLevel", &Parameters::SetSecurityLevel, py::arg("security_level"))
            .def("SetBatchSize", &Parameters::SetBatchSize, py::arg("batch_size"));


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
            .def("GetRingDimension", &PythonContext::GetRingDim);


    py::class_<Cipher>(m, "Ciphertext")
            .def(py::init<>());

    m.def("InitializeEnvironment", &InitializePythonEnvironment, py::arg("context"), py::arg("batch_size"), py::arg("initial_channels"));

}