# NeuralPy
NeuralPY is a library which creates Python wrappers around the [NeuralOFHE](https://github.com/LinusHenke99/NeuralOFHE)
library which in turn uses the [OpenFHE](https://github.com/openfheorg/openfhe-development) library in order to implement 
machine learning operators using homomorphic encryption in order to do inference on encrypted data. The Python wrappers
are created using [Pybind11](https://pybind11.readthedocs.io/en/stable/) in order to take advantage of the machine 
learning tools available in Python.

## Dependencies
- [Pybind11](https://github.com/pybind/pybind11)
- [OpenFHE](https://github.com/openfheorg/openfhe-development)
- [NeuralOFHE](https://github.com/LinusHenke99/NeuralOFHE)
- [CMake 3.12 or newer](https://cmake.org/)

## Installation
The project is set up as using CMake, so the project can be installed by executing the following commands
```
mkdir build && cd build
cmake ..
make && make install
```
the `make install` command must probably be issued with sudo privileges.

## 
