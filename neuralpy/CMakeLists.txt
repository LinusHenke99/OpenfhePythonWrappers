cmake_minimum_required(VERSION 3.12)

project(neuralpy)
set(CMAKE_CXX_STANDARD 20)

option(BUILD_STATIC OFF)
find_package(OpenFHE REQUIRED)
set( CMAKE_CXX_FLAGS "-fPIC ${OpenFHE_CXX_FLAGS}")
message(${CMAKE_CXX_FLAGS})
link_directories( ${OpenFHE_LIBDIR})
set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS})
link_libraries( ${OpenFHE_SHARED_LIBRARIES})

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )

find_package(pybind11 CONFIG)
find_package(NeuralOFHE REQUIRED)
pybind11_add_module(neuralpy MODULE neuralpy.cpp)

target_link_libraries(neuralpy PRIVATE NeuralOFHE)

find_package(Python REQUIRED COMPONENTS Interpreter Development)

execute_process(
        COMMAND "${Python_EXECUTABLE}" -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())"
        OUTPUT_VARIABLE PYTHON_SITE_PACKAGES
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

message(STATUS "Python site packages directory: ${PYTHON_SITE_PACKAGES}")
install(TARGETS neuralpy LIBRARY DESTINATION ${PYTHON_SITE_PACKAGES})

file(MAKE_DIRECTORY example_code/keys)