# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

# DNS
add_executable(dns-test dns.c)
target_include_directories(dns-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(dns-test cunit)
target_link_libraries(dns-test packet_utils)
target_link_libraries(dns-test header dns)
install(TARGETS dns-test DESTINATION ${TEST_BIN_DIR})
