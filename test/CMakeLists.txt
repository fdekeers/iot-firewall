# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

# Set test output directory
set(TEST_BIN_DIR ${BIN_DIR}/test)
set(EXECUTABLE_OUTPUT_PATH ${TEST_BIN_DIR})

# DNS table test
add_executable(dns_table-test dns_table.c)
target_include_directories(dns_table-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(dns_table-test cunit)
target_link_libraries(dns_table-test ${LIB_DIR}/libhashmap.a)
target_link_libraries(dns_table-test dns_table)
install(TARGETS dns_table-test DESTINATION ${TEST_BIN_DIR})

# Test subdirectories
add_subdirectory(parsers)
