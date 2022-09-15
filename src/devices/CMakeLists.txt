# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

# Set bin output directory
set(DEVICES_BIN_DIR ${BIN_DIR}/devices)
set(EXECUTABLE_OUTPUT_PATH ${DEVICES_BIN_DIR})

# Xiaomi camera
add_executable(xiaomi-cam xiaomi-cam/xiaomi-cam.c)
target_link_libraries(xiaomi-cam map_domain_ip nfqueue)
target_link_libraries(xiaomi-cam ${PARSERS})
target_include_directories(xiaomi-cam PRIVATE ${INCLUDE_DIR})
install(TARGETS xiaomi-cam DESTINATION ${DEVICES_BIN_DIR})
