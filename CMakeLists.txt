# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

# Project name
project(iot-firewall C)

# Set project directories 
set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR})
set(INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(BIN_DIR ${PROJECT_SOURCE_DIR}/bin)
set(LIB_DIR ${PROJECT_SOURCE_DIR}/lib)
set(EXECUTABLE_OUTPUT_PATH ${BIN_DIR})

# Set compiler flags
add_compile_options(-Wall -Werror)

# Custom parsers
set(PARSERS header dns dhcp http igmp ssdp coap)

# Subdirectories containing code
add_subdirectory(src)
add_subdirectory(devices)
add_subdirectory(test)
