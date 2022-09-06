# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

set(SOURCE_FILES dns.c)

add_executable(test-dns ${SOURCE_FILES})
target_link_libraries(test-dns cunit)
target_link_libraries(test-dns packet_utils)
target_link_libraries(test-dns header dns)
target_include_directories(test-dns PRIVATE ${INCLUDE_DIR})
install(TARGETS test-dns DESTINATION ${TEST_BIN_DIR})
