# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

set(TEST_BIN_DIR ${BIN_DIR}/devices/test)
set(EXECUTABLE_OUTPUT_PATH ${TEST_BIN_DIR})

# Queue test-queue
add_executable(test-queue nfqueues/test-queue.c)
target_link_libraries(test-queue nfqueue)
target_include_directories(test-queue PRIVATE ${INCLUDE_DIR})
install(TARGETS test-queue DESTINATION ${EXECUTABLE_OUTPUT_PATH})
