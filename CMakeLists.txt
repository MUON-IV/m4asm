cmake_minimum_required(VERSION 3.1...3.25)

project(
  m4asm
  VERSION 1.0
  LANGUAGES C)

if (MSVC)
add_executable(m4asm src/m4asm.c src/getopt/getopt.c)
target_link_libraries(m4asm ws2_32 wsock32)
else()
add_executable(m4asm src/m4asm.c)
endif()