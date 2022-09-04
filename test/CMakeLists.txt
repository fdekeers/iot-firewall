# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

# Set test output directory
set(TEST_BIN_DIR ${BIN_DIR}/test)
set(EXECUTABLE_OUTPUT_PATH ${TEST_BIN_DIR})

# Compile base nfqueue test
set(SOURCE_FILES basic-queue.c)
add_executable(basic-queue ${SOURCE_FILES})
target_link_libraries(basic-queue netfilter_queue)
install(TARGETS basic-queue DESTINATION ${TEST_BIN_DIR})

# Test subdirectories
add_subdirectory(parsers)
