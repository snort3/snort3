
cmake_minimum_required(VERSION 2.8)
project (snort CXX C)

set (SNORT_VERSION_MAJOR 2)
set (SNORT_VERSION_MINOR 10)
set (SNORT_VERSION_BUILD  113)
set (VERSION "${SNORT_VERSION_MAJOR}.${SNORT_VERSION_MINOR}.${SNORT_VERSION_BUILD}")

# ensure cmake will look in the cmake directory for configuration files
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")
set (INCLUDE_INSTALL_PATH "include/${CMAKE_PROJECT_NAME}")


include (cmake/macros.cmake)
include (cmake/create_options.cmake)
include (cmake/include_libraries.cmake)
include (cmake/platforms.cmake)
include (cmake/configure_options.cmake)
include (cmake/CheckCXX11Features.cmake)
include (cmake/sanity_checks.cmake)


include(GenerateExportHeader)
#add_compiler_export_flags ()  # hidden visiblity - TODO --> PLAY WITH THESE FLAGS!!
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX11_COMPILER_FLAGS}") # c++11 flag


# include this directory for the config.h file. created in sanityChecks.cmake
include_directories(${PROJECT_BINARY_DIR})

add_subdirectory (etc)
add_subdirectory (src)
add_subdirectory (tools)
add_subdirectory (lua)
add_subdirectory (doc)



# Miscelaneous stuff.  Does NOT directly effect snort's building environment

include (cmake/packaging_data.cmake)
include (cmake/create_pkg_config.cmake)


# uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

