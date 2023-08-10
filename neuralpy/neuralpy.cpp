#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "include/ModuleDefinitions.h"
#include "include/WrapperFunctions.h"


namespace py = pybind11;


PYBIND11_MODULE(neuralpy, m) {
    defineEnums(m);
    defineBasicOpenFHEModules(m);
    defineNeuralOFHETypes(m);
    m.def("SetContext", &SetPythonContext, py::arg("context"));
    m.def("MakeContext", &MakeContext, py::arg("parameters"));
    m.def("GetContext", &GetContext, py::arg("ciphertext"));
}