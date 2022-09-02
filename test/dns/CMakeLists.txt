# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

set(SOURCE_FILES print-dns.c)

add_executable(print-dns ${SOURCE_FILES})
target_link_libraries(print-dns header dns)
target_include_directories(print-dns PRIVATE ${INCLUDE_DIR})
install(TARGETS print-dns DESTINATION ${TEST_BIN_DIR})
