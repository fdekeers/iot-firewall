# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

# Project name
project(iot-firewall)

# Set project directories 
set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR})
set(INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(BIN_DIR ${PROJECT_SOURCE_DIR}/bin)
set(LIB_DIR ${PROJECT_SOURCE_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${BIN_DIR})

include_directories(${INCLUDE_DIR})

add_executable(iot-firewall src/main.c)

