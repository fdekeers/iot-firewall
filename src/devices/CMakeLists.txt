# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

# Set bin output directory
set(DEVICES_BIN_DIR ${BIN_DIR}/devices)
set(EXECUTABLE_OUTPUT_PATH ${DEVICES_BIN_DIR})

# Add all devices subdirectories
add_subdirectory(xiaomi-cam)
