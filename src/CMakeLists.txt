# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

add_subdirectory(parsers)

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

# dns_map
add_library(dns_map STATIC ${INCLUDE_DIR}/dns_map.h dns_map.c)
target_include_directories(dns_map PRIVATE ${INCLUDE_DIR})
target_link_libraries(dns_map ${LIB_DIR}/libhashmap.a)
install(TARGETS dns_map DESTINATION ${LIB_DIR})

# rule_utils
add_library(rule_utils STATIC ${INCLUDE_DIR}/rule_utils.h rule_utils.c)
target_include_directories(rule_utils PRIVATE ${INCLUDE_DIR})
install(TARGETS rule_utils DESTINATION ${LIB_DIR})
