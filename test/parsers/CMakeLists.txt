# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

# DNS
add_executable(dns-test dns.c)
target_include_directories(dns-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(dns-test cunit)
target_link_libraries(dns-test packet_utils)
target_link_libraries(dns-test header dns)
install(TARGETS dns-test DESTINATION ${TEST_BIN_DIR})

# DHCP
add_executable(dhcp-test dhcp.c)
target_include_directories(dhcp-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(dhcp-test cunit)
target_link_libraries(dhcp-test packet_utils)
target_link_libraries(dhcp-test header dhcp)
install(TARGETS dhcp-test DESTINATION ${TEST_BIN_DIR})

# HTTP
add_executable(http-test http.c)
target_include_directories(http-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(http-test cunit)
target_link_libraries(http-test packet_utils)
target_link_libraries(http-test header http)
install(TARGETS http-test DESTINATION ${TEST_BIN_DIR})
