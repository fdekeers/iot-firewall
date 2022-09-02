# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

# Set test output directory
set(TEST_BIN_DIR ${BIN_DIR}/test)
set(EXECUTABLE_OUTPUT_PATH ${TEST_BIN_DIR})

# Compile base nfqueue test
set(SOURCE_FILES nfqueue.c)
add_executable(nfqueue ${SOURCE_FILES})
target_link_libraries(nfqueue netfilter_queue)
install(TARGETS nfqueue DESTINATION ${TEST_BIN_DIR})

# Test subdirectories
add_subdirectory(dns)
