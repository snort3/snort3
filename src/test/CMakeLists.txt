## Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
##
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


if ( BUILD_UNIT_TESTS )

find_package(CHECK REQUIRED)
include_directories(${CHECK_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})  # for generated files


#  Generating build_decl.h  Will rebuild every time 'make' is run
add_custom_target(build_suit_decl ALL
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/build_list.sh ${CMAKE_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "building suite_decl.h"
)
add_custom_command( OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/suite_decl.h
    COMMAND ${CMAKE_COMMAND} -E touch_nocreate ${CMAKE_CURRENT_BINARY_DIR}/suite_decl.h
    DEPENDS build_suit_decl
)


#  Generating suite_list.h  Will rebuild every time 'make' is run
add_custom_target(build_suite_list ALL
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/build_decl.sh ${CMAKE_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "building suite_list.h"
)
add_custom_command( OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/suite_list.h
    COMMAND ${CMAKE_COMMAND} -E touch_nocreate ${CMAKE_CURRENT_BINARY_DIR}/suite_list.h
    DEPENDS build_suite_list
)

add_library(unit_tests STATIC
    ${CMAKE_CURRENT_BINARY_DIR}/suite_decl.h
    ${CMAKE_CURRENT_BINARY_DIR}/suite_list.h
    sfip_test.cc
    sfrf_test.cc
    sfrt_test.cc
    sfthd_test.cc
    unit_test.cc
    unit_test.h
)

target_link_libraries(unit_tests
    ${CHECK_LIBRARIES}
)

set_source_files_properties( unit_test.cc PROPERTIES
    OBJECT_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/suite_decl.h
    OBJECT_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/suite_list.h
)

endif()
