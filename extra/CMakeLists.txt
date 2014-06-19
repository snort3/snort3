
cmake_minimum_required(VERSION 2.8)
project(snort CXX C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SNORT snort)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SNORT_CFLAGS}")

string (REPLACE ";" " " CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS}")
string (REPLACE "-DHAVE_CONFIG_H" " " CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS}")
message(STATUS "${CMAKE_CXX_FLAGS}")

add_subdirectory(src)
