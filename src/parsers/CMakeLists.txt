# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

set(INCLUDE_PARSERS_DIR ${INCLUDE_DIR}/parsers)

# Header parser
add_library(header STATIC ${INCLUDE_PARSERS_DIR}/header.h header.c)
target_include_directories(header PRIVATE ${INCLUDE_PARSERS_DIR})
install(TARGETS header DESTINATION ${LIB_DIR})
install(FILES ${INCLUDE_PARSERS_DIR}/header.h DESTINATION ${INCLUDE_DIR})
# DNS parser
add_library(dns STATIC ${INCLUDE_PARSERS_DIR}/dns.h dns.c)
target_include_directories(dns PRIVATE ${INCLUDE_PARSERS_DIR})
install(TARGETS dns DESTINATION ${LIB_DIR})
install(FILES ${INCLUDE_PARSERS_DIR}/dns.h DESTINATION ${INCLUDE_DIR})
