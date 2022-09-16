# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

set(XIAOMI_CAM_BIN_DIR ${BIN_DIR}/devices/xiaomi-cam)
set(EXECUTABLE_OUTPUT_PATH ${XIAOMI_CAM_BIN_DIR})

# Queue 1: DHCP
add_executable(xiaomi-cam-1 nfqueues/1-dhcp.c)
target_link_libraries(xiaomi-cam-1 nfqueue)
target_link_libraries(xiaomi-cam-1 ${PARSERS})
target_include_directories(xiaomi-cam-1 PRIVATE ${INCLUDE_DIR})
install(TARGETS xiaomi-cam-1 DESTINATION ${XIAOMI_CAM_BIN_DIR})

# Queue 2: DNS
add_executable(xiaomi-cam-2 nfqueues/2-dns.c)
target_link_libraries(xiaomi-cam-2 nfqueue)
target_link_libraries(xiaomi-cam-2 ${PARSERS})
target_include_directories(xiaomi-cam-2 PRIVATE ${INCLUDE_DIR})
install(TARGETS xiaomi-cam-2 DESTINATION ${XIAOMI_CAM_BIN_DIR})
