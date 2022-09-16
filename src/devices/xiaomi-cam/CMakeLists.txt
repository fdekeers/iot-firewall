# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

# Xiaomi camera
add_executable(xiaomi-cam-1 nfqueues/1-dhcp.c)
target_link_libraries(xiaomi-cam-1 nfqueue)
target_link_libraries(xiaomi-cam-1 ${PARSERS})
target_include_directories(xiaomi-cam-1 PRIVATE ${INCLUDE_DIR})
install(TARGETS xiaomi-cam-1 DESTINATION ${DEVICES_BIN_DIR})
