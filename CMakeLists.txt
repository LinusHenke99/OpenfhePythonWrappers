cmake_minimum_required(VERSION 3.12)

project(NeuralPY)
set(CMAKE_CXX_STANDARD 20)

option(BUILD_STATIC OFF)
find_package(OpenFHE REQUIRED)
set( CMAKE_CXX_FLAGS "-fPIC ${OpenFHE_CXX_FLAGS}")
message(${CMAKE_CXX_FLAGS})
link_directories( ${OpenFHE_LIBDIR})
set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS})
link_libraries( ${OpenFHE_SHARED_LIBRARIES})

link_libraries(NeuralOFHE)

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )

find_package(pybind11 CONFIG)
find_package(NeuralOFHE REQUIRED)
pybind11_add_module(neuralpy src/neuralpy.cpp)