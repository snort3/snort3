cmake_minimum_required (VERSION 2.8.11)
project (snort CXX C)

set (VERSION_MAJOR 3)
set (VERSION_MINOR 0)
set (VERSION_BUILD 0)
set (VERSION_RELEASE a4)
set (VERSION
    "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_BUILD}-${VERSION_RELEASE}")

set (INCLUDE_SUFFIX "${CMAKE_PROJECT_NAME}")
set (INCLUDE_INSTALL_PATH "include/${INCLUDE_SUFFIX}")

set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include (cmake/macros.cmake)
include (cmake/create_options.cmake)
include (cmake/include_libraries.cmake)
include (cmake/platforms.cmake)
include (cmake/configure_options.cmake)
include (cmake/CheckCXX11Features.cmake)
#include (cmake/compiler_features.cmake)
include (cmake/sanity_checks.cmake)

configure_file (
    "${PROJECT_SOURCE_DIR}/config.cmake.h.in"
    "${PROJECT_BINARY_DIR}/config.h"
    )

add_definitions( -DHAVE_CONFIG_H )

# CMAKE_CXX_* properties aren't supported in 2.x :(
# set (CMAKE_CXX_STANDARD 11)
# set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX11_COMPILER_FLAGS}")

# FIXIT - there is probably a better way to do this
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")

# Apply sanitizer compiler and linker flags
set ( CMAKE_C_FLAGS "${SANITIZER_CXXFLAGS} ${CMAKE_C_FLAGS}" )
set ( CMAKE_CXX_FLAGS "${SANITIZER_CXXFLAGS} ${CMAKE_CXX_FLAGS}" )

include_directories (${PROJECT_BINARY_DIR})
include_directories (${PROJECT_SOURCE_DIR})

if (ENABLE_UNIT_TESTS)
    include(CTest)
    add_custom_target (check COMMAND ${CMAKE_CTEST_COMMAND})
    add_dependencies (check snort)
    #add_test (catch_tests ${CMAKE_CURRENT_BINARY_DIR}/src/snort --catch-test all)
endif (ENABLE_UNIT_TESTS)

add_subdirectory (src)
add_subdirectory (tools)
add_subdirectory (lua)
add_subdirectory (doc)
add_subdirectory (daqs)

# Miscellaneous stuff.  Does NOT directly effect snort's building environment
include (cmake/packaging_data.cmake)
include (cmake/create_pkg_config.cmake)

# uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
