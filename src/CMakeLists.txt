# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

add_subdirectory(parsers)
set(PARSERS header dns)

# Build libraries

# nfqueue
add_library(nfqueue STATIC ${INCLUDE_DIR}/nfqueue.h nfqueue.c)
target_include_directories(nfqueue PRIVATE ${INCLUDE_DIR})
install(TARGETS nfqueue DESTINATION ${LIB_DIR})

# packet_utils
add_library(packet_utils STATIC ${INCLUDE_DIR}/packet_utils.h packet_utils.c)
target_include_directories(packet_utils PRIVATE ${INCLUDE_DIR})
install(TARGETS packet_utils DESTINATION ${LIB_DIR})

# dns_table
add_library(dns_table STATIC ${INCLUDE_DIR}/dns_table.h dns_table.c)
target_include_directories(dns_table PRIVATE ${INCLUDE_DIR})
target_link_libraries(dns_table ${LIB_DIR}/libhashmap.a)
install(TARGETS dns_table DESTINATION ${LIB_DIR})

# Build executable
add_executable(iot-firewall main.c)
target_link_libraries(iot-firewall netfilter_queue)
target_link_libraries(iot-firewall ${LIB_DIR}/libhashmap.a)
target_link_libraries(iot-firewall nfqueue packet_utils dns_table)
target_link_libraries(iot-firewall ${PARSERS})
target_include_directories(iot-firewall PRIVATE ${INCLUDE_DIR})
install(TARGETS iot-firewall DESTINATION ${BIN_DIR})
