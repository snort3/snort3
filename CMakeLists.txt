## Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License Version 2 as
## published by the Free Software Foundation.  You may not use, modify or
## distribute this program under any other version of the GNU General
## Public License.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


cmake_minimum_required(VERSION 2.9)
project (snort CXX C)

set (SNORT_VERSION_MAJOR 3)
set (SNORT_VERSION_MINOR 0)
set (SNORT_VERSION_BUILD  0-a1)
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


set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX11_COMPILER_FLAGS}") # c++11 flag


# include this directory for the config.h file. created in sanityChecks.cmake
include_directories(${PROJECT_BINARY_DIR})

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


# Test plugins in the 'Extra' directory!!
if (BUILD_EXTRA_PLUGINS)
    if (${CMAKE_GENERATOR} MATCHES "Make")
        add_subdirectory(extra)
    endif()
endif (BUILD_EXTRA_PLUGINS)
