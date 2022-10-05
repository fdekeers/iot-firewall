# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

set(XIAOMI_CAM_BIN_DIR ${BIN_DIR}/devices/xiaomi-cam)
set(EXECUTABLE_OUTPUT_PATH ${XIAOMI_CAM_BIN_DIR})

# Queue 1: DHCP
add_executable(xiaomi-cam-dhcp nfqueues/dhcp.c)
target_link_libraries(xiaomi-cam-dhcp pthread)
target_link_libraries(xiaomi-cam-dhcp nfqueue packet_utils)
target_link_libraries(xiaomi-cam-dhcp ${PARSERS})
target_include_directories(xiaomi-cam-dhcp PRIVATE ${INCLUDE_DIR})
install(TARGETS xiaomi-cam-dhcp DESTINATION ${XIAOMI_CAM_BIN_DIR})

# Queue 2: DNS
add_executable(xiaomi-cam-dns nfqueues/dns.c)
target_link_libraries(xiaomi-cam-dns pthread)
target_link_libraries(xiaomi-cam-dns nfqueue packet_utils)
target_link_libraries(xiaomi-cam-dns ${PARSERS})
target_include_directories(xiaomi-cam-dns PRIVATE ${INCLUDE_DIR})
install(TARGETS xiaomi-cam-dns DESTINATION ${XIAOMI_CAM_BIN_DIR})

# Queue 3: HTTP
add_executable(xiaomi-cam-http nfqueues/http.c)
target_link_libraries(xiaomi-cam-http pthread)
target_link_libraries(xiaomi-cam-http nfqueue packet_utils)
target_link_libraries(xiaomi-cam-http ${PARSERS})
target_include_directories(xiaomi-cam-http PRIVATE ${INCLUDE_DIR})
install(TARGETS xiaomi-cam-http DESTINATION ${XIAOMI_CAM_BIN_DIR})

# Queue 4: Open app local
add_executable(xiaomi-cam-open-app-local nfqueues/open-app-local.c)
target_link_libraries(xiaomi-cam-open-app-local pthread)
target_link_libraries(xiaomi-cam-open-app-local nfqueue packet_utils)
target_link_libraries(xiaomi-cam-open-app-local ${PARSERS})
target_include_directories(xiaomi-cam-open-app-local PRIVATE ${INCLUDE_DIR})
install(TARGETS xiaomi-cam-open-app-local DESTINATION ${XIAOMI_CAM_BIN_DIR})
