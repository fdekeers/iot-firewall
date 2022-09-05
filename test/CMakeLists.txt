# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

# Set test output directory
set(TEST_BIN_DIR ${BIN_DIR}/test)
set(EXECUTABLE_OUTPUT_PATH ${TEST_BIN_DIR})

# Compile base nfqueue test
set(SOURCE_FILES basic-queue.c)
set(LIBRARIES nfqueue packet-utils)
add_executable(basic-queue ${SOURCE_FILES})
target_include_directories(basic-queue PRIVATE ${INCLUDE_DIR} ${INCLUDE_PARSERS_DIR})
target_link_libraries(basic-queue netfilter_queue ${LIBRARIES})
install(TARGETS basic-queue DESTINATION ${TEST_BIN_DIR})

# Test subdirectories
add_subdirectory(parsers)
