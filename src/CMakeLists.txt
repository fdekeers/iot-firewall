# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

add_subdirectory(parsers)
set(LIB_SRC_FILES nfqueue.c)
set(EXEC_SRC_FILES main.c)
set(PARSERS header dns)

# Build libraries
add_library(nfqueue STATIC ${INCLUDE_DIR}/nfqueue.h nfqueue.c)
target_include_directories(nfqueue PRIVATE ${INCLUDE_DIR})
install(TARGETS nfqueue DESTINATION ${LIB_DIR})
install(FILES ${INCLUDE_PARSERS_DIR}/header.h DESTINATION ${INCLUDE_DIR})

# Build executable
add_executable(iot-firewall main.c)
target_link_libraries(iot-firewall ${LIB_DIR}/libhashmap.a)
target_link_libraries(iot-firewall nfqueue)
target_link_libraries(iot-firewall ${PARSERS})
target_include_directories(iot-firewall PRIVATE ${INCLUDE_DIR})
install(TARGETS iot-firewall DESTINATION ${BIN_DIR})
