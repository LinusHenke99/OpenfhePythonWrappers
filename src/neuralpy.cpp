#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "../include/ModuleDefinitions.h"

// #include "../include/WrapperFunctions.h"


namespace py = pybind11;


PYBIND11_MODULE(neuralpy, m) {
    defineBasicOpenFHEModules(m);

    defineNeuralOFHETypes(m);

    m.def("SetContext", &InitializePythonEnvironment, py::arg("context"));

}