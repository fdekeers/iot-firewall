# Minimum required CMake version
cmake_minimum_required(VERSION 3.2)

set(PARSERS_DIR parsers)

add_subdirectory(parsers)
set(SOURCE_FILES main.c)

add_executable(iot-firewall ${SOURCE_FILES})
target_link_libraries(iot-firewall ${LIB_DIR}/libhashmap.a)
target_include_directories(iot-firewall PRIVATE ${INCLUDE_DIR})
install(TARGETS iot-firewall DESTINATION ${BIN_DIR})
