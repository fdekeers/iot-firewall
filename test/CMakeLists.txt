# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

# Set test output directory
set(TEST_BIN_DIR ${BIN_DIR}/test)
set(EXECUTABLE_OUTPUT_PATH ${TEST_BIN_DIR})

# Domain - IP mapping test
add_executable(map_domain_ip-test map_domain_ip.c)
target_include_directories(map_domain_ip-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(map_domain_ip-test cunit)
target_link_libraries(map_domain_ip-test ${LIB_DIR}/libhashmap.a)
target_link_libraries(map_domain_ip-test map_domain_ip)
install(TARGETS map_domain_ip-test DESTINATION ${TEST_BIN_DIR})

# Packet utils test
add_executable(packet_utils-test packet_utils.c)
target_include_directories(packet_utils-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(packet_utils-test cunit)
target_link_libraries(packet_utils-test packet_utils)
install(TARGETS packet_utils-test DESTINATION ${TEST_BIN_DIR})

# nftables utilitairies test
add_executable(rule_utils-test rule_utils.c)
target_include_directories(rule_utils-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(rule_utils-test cunit)
target_link_libraries(rule_utils-test rule_utils)
install(TARGETS rule_utils-test DESTINATION ${TEST_BIN_DIR})

# Test subdirectories
add_subdirectory(parsers)
