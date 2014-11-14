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


include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

add_subdirectory(data)
add_subdirectory(keyword_states)
add_subdirectory(preprocessor_states)
add_subdirectory(output_states)
add_subdirectory(config_states)
add_subdirectory(rule_states)
add_subdirectory(helpers)

if (BUILD_UNIT_TESTS)
    add_subdirectory(tests)
endif()

add_executable( snort2lua
    conversion_state.h
    conversion_defines.h
    init_state.h
    snort2lua.cc
    init_state.cc
)

target_link_libraries( snort2lua
    conversion_data
    snort2lua_helpers
    keyword_states
    output_states
    preprocessor_states
    rule_states
)

install (TARGETS snort2lua
    RUNTIME DESTINATION bin
)
