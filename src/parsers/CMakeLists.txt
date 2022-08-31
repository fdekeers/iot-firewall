# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

set(INCLUDE_PARSERS_DIR ${INCLUDE_DIR}/parsers)
set(SOURCE_FILES
    ${INCLUDE_PARSERS_DIR}/dns.h dns.c
)

add_library(dns STATIC ${SOURCE_FILES})
target_include_directories(dns PRIVATE ${INCLUDE_PARSERS_DIR})
install(TARGETS dns DESTINATION ${LIB_DIR})
install(FILES ${INCLUDE_PARSERS_DIR}/dns.h DESTINATION ${INCLUDE_DIR})
