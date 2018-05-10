cmake_minimum_required (VERSION 3.4.3)
project (snort CXX C)

set (VERSION_MAJOR 3)
set (VERSION_MINOR 0)
set (VERSION_PATCH 0)
set (VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

set (CMAKE_C_STANDARD 99)
set (CMAKE_C_STANDARD_REQUIRED ON)
set (CMAKE_C_EXTENSIONS ON)

set (CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
# Pull in definitions of various install directories
include (GNUInstallDirs)
include (${CMAKE_MODULE_PATH}/macros.cmake)
include (${CMAKE_MODULE_PATH}/create_options.cmake)
include (${CMAKE_MODULE_PATH}/include_libraries.cmake)
include (${CMAKE_MODULE_PATH}/platforms.cmake)
include (${CMAKE_MODULE_PATH}/configure_options.cmake)
#include (${CMAKE_MODULE_PATH}/compiler_features.cmake)
include (${CMAKE_MODULE_PATH}/sanity_checks.cmake)

set (INSTALL_SUFFIX "${CMAKE_PROJECT_NAME}")
set (INCLUDE_INSTALL_PATH "${CMAKE_INSTALL_INCLUDEDIR}/${INSTALL_SUFFIX}")
set (PLUGIN_INSTALL_PATH "${CMAKE_INSTALL_LIBDIR}/${INSTALL_SUFFIX}")

configure_file (
    "${PROJECT_SOURCE_DIR}/config.cmake.h.in"
    "${PROJECT_BINARY_DIR}/config.h"
)

add_definitions( -DHAVE_CONFIG_H )

# Set these after all tests are done but *before* any subdirectories are included
#  or other targets declared.
string(APPEND CMAKE_C_FLAGS " ${EXTRA_C_FLAGS}")
string(APPEND CMAKE_CXX_FLAGS " ${EXTRA_CXX_FLAGS}")
string(APPEND CMAKE_EXE_LINKER_FLAGS " ${EXTRA_LINKER_FLAGS}")
string(APPEND CMAKE_MODULE_LINKER_FLAGS " ${EXTRA_LINKER_FLAGS}")
foreach (EXTRA_LIBRARY IN LISTS EXTRA_LIBRARIES)
    link_libraries(${EXTRA_LIBRARY})
endforeach (EXTRA_LIBRARY)

include_directories (${PROJECT_BINARY_DIR})
include_directories (${PROJECT_SOURCE_DIR})

if (ENABLE_UNIT_TESTS)
    include(CTest)
    add_custom_target (check COMMAND ${CMAKE_CTEST_COMMAND})
endif (ENABLE_UNIT_TESTS)

add_subdirectory (src)
add_subdirectory (tools)
add_subdirectory (lua)
add_subdirectory (doc)
add_subdirectory (daqs)

# Miscellaneous stuff.  Does NOT directly affect Snort's build environment.
include (${CMAKE_MODULE_PATH}/packaging_data.cmake)
include (${CMAKE_MODULE_PATH}/create_pkg_config.cmake)

# uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

message("
-------------------------------------------------------
${CMAKE_PROJECT_NAME} version ${VERSION}

Install options:
    prefix:     ${CMAKE_INSTALL_PREFIX}
    includes:   ${CMAKE_INSTALL_FULL_INCLUDEDIR}/${INSTALL_SUFFIX}
    plugins:    ${CMAKE_INSTALL_FULL_LIBDIR}/${INSTALL_SUFFIX}

Compiler options:
    CC:             ${CMAKE_C_COMPILER}
    CXX:            ${CMAKE_CXX_COMPILER}
    CFLAGS:         ${CMAKE_C_FLAGS}
    CXXFLAGS:       ${CMAKE_CXX_FLAGS}
    EXE_LDFLAGS:    ${CMAKE_EXE_LINKER_FLAGS}
    MODULE_LDFLAGS: ${CMAKE_MODULE_LINKER_FLAGS}

Feature options:\
")

if (HAVE_FLATBUFFERS)
    message("\
    Flatbuffers:    ON")
else ()
    message("\
    Flatbuffers:    OFF")
endif ()

if (HAVE_HYPERSCAN)
    message("\
    Hyperscan:      ON")
else ()
    message("\
    Hyperscan:      OFF")
endif ()

if (HAVE_ICONV)
    message("\
    ICONV:          ON")
else ()
    message("\
    ICONV:          OFF")
endif ()

if (HAVE_LZMA)
    message("\
    LZMA:           ON")
else ()
    message("\
    LZMA:           OFF")
endif ()

if (HAVE_SAFEC AND SAFEC_ENABLED)
    message("\
    SafeC:          ON")
else ()
    message("\
    SafeC:          OFF")
endif ()

if (HAVE_TCMALLOC)
    message("\
    TCMalloc:       ON")
else ()
    message("\
    TCMalloc:       OFF")
endif ()

if (HAVE_UUID)
    message("\
    UUID:           ON")
else ()
    message("\
    UUID:           OFF")
endif ()

message("-------------------------------------------------------\n")
