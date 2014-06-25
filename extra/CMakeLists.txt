
cmake_minimum_required(VERSION 2.8.8)
project(snort_extra CXX C)


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}")

# Look for Snort using pkg-config and our own find-snort module
find_package(PkgConfig REQUIRED)
pkg_check_modules(SNORT_PKG_MODULE snort)


if (SNORT_PKG_MODULE_FOUND)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SNORT_PKG_MODULE_CFLAGS}")
    find_package(SNORT QUIET)
else()
    find_package(SNORT REQUIRED)
endif()

if ((NOT SNORT_FOUND) AND (NOT SNORT_PKG_MODULE_FOUND))
    message(FATAL_ERROR "Unable to find Snort includes!!")
endif()

string (REPLACE ";" " " CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS}")
string (REPLACE "-DHAVE_CONFIG_H" " " CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS}")
message(STATUS "${CMAKE_CXX_FLAGS}")

add_subdirectory(src)



# adding make unisntall
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
