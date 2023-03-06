cmake_minimum_required(VERSION 3.1...3.25)

project(
  m4asm
  VERSION 1.0
  LANGUAGES C)

if (MSVC)
find_library(WSOCK32_LIBRARY wsock32)
find_library(WS2_32_LIBRARY ws2_32)
add_executable(m4asm src/m4asm.c src/getopt/getopt.c)
target_link_libraries(m4asm ${WSOCK32_LIBRARY} ${WS2_32_LIBRARY})
else()
add_executable(m4asm src/m4asm.c)
endif()