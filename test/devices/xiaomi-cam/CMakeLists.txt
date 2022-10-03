# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

# Set output directory
set(XIAOMI_CAM_BIN_DIR ${BIN_DIR}/devices/xiaomi-cam)
set(EXECUTABLE_OUTPUT_PATH ${XIAOMI_CAM_BIN_DIR})

# Protocol parsers
set(PARSERS header dns dhcp)

# Compile test queue
add_executable(test nfqueue.c)
target_include_directories(test PRIVATE ${INCLUDE_DIR})
target_link_libraries(test nfqueue)
target_link_libraries(test ${PARSERS})
install(TARGETS test DESTINATION ${XIAOMI_CAM_BIN_DIR})
