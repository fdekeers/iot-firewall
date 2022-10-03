# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

set(XIAOMI_CAM_BIN_DIR ${BIN_DIR}/devices/xiaomi-cam)
set(EXECUTABLE_OUTPUT_PATH ${XIAOMI_CAM_BIN_DIR})

# Queue 1: DHCP
add_executable(xiaomi-cam-1-dhcp nfqueues/1-dhcp.c)
target_link_libraries(xiaomi-cam-1-dhcp nfqueue)
target_link_libraries(xiaomi-cam-1-dhcp ${PARSERS})
target_include_directories(xiaomi-cam-1-dhcp PRIVATE ${INCLUDE_DIR})
install(TARGETS xiaomi-cam-1-dhcp DESTINATION ${XIAOMI_CAM_BIN_DIR})

# Queue 2: DNS
add_executable(xiaomi-cam-2-dns nfqueues/2-dns.c)
target_link_libraries(xiaomi-cam-2-dns nfqueue)
target_link_libraries(xiaomi-cam-2-dns ${PARSERS})
target_include_directories(xiaomi-cam-2-dns PRIVATE ${INCLUDE_DIR})
install(TARGETS xiaomi-cam-2-dns DESTINATION ${XIAOMI_CAM_BIN_DIR})

# Queue 3: HTTP
add_executable(xiaomi-cam-3-http nfqueues/3-http.c)
target_link_libraries(xiaomi-cam-3-http nfqueue)
target_link_libraries(xiaomi-cam-3-http ${PARSERS})
target_include_directories(xiaomi-cam-3-http PRIVATE ${INCLUDE_DIR})
install(TARGETS xiaomi-cam-3-http DESTINATION ${XIAOMI_CAM_BIN_DIR})
