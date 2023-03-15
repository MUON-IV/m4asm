cmake_minimum_required(VERSION 3.1...3.25)

project(
  m4asm
  VERSION 1.0
  LANGUAGES C)

if (MSVC)
find_package(unofficial-pcre CONFIG REQUIRED)
add_executable(m4asm src/m4asm.c src/label.c src/lib/getopt/getopt.c src/lib/strsep/strsep.c)
target_link_libraries(m4asm ws2_32 wsock32 unofficial::pcre::pcre unofficial::pcre::pcre16 unofficial::pcre::pcre32 unofficial::pcre::pcrecpp)
else()
add_executable(m4asm src/m4asm.c src/label.c src/lib/getopt/getopt.c src/lib/strsep/strsep.c)
target_link_libraries(m4asm pcre)
endif()