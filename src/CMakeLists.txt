# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

add_subdirectory(parsers)
set(PARSERS header dns dhcp http)

add_subdirectory(devices)
set(DEVICES xiaomi-cam)

# Build libraries

# nfqueue
add_library(nfqueue STATIC ${INCLUDE_DIR}/nfqueue.h nfqueue.c)
target_link_libraries(nfqueue netfilter_queue)
target_include_directories(nfqueue PRIVATE ${INCLUDE_DIR})
install(TARGETS nfqueue DESTINATION ${LIB_DIR})

# packet_utils
add_library(packet_utils STATIC ${INCLUDE_DIR}/packet_utils.h packet_utils.c)
target_include_directories(packet_utils PRIVATE ${INCLUDE_DIR})
install(TARGETS packet_utils DESTINATION ${LIB_DIR})

# map_domain_ip
add_library(map_domain_ip STATIC ${INCLUDE_DIR}/map_domain_ip.h map_domain_ip.c)
target_include_directories(map_domain_ip PRIVATE ${INCLUDE_DIR})
target_link_libraries(map_domain_ip ${LIB_DIR}/libhashmap.a)
install(TARGETS map_domain_ip DESTINATION ${LIB_DIR})
