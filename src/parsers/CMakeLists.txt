# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

set(INCLUDE_PARSERS_DIR ${INCLUDE_DIR}/parsers)

add_library(dns dns.c)
target_include_directories(dns PRIVATE ${INCLUDE_PARSERS_DIR})
