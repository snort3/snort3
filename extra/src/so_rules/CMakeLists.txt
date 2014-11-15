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


# Use this macro to create text files
macro (create_txt_header txt_file hdr_file)

    add_custom_command( OUTPUT ${hdr_file}
        COMMAND
            "${SNORT_EXECUTABLE}" --rule-to-text < "${CMAKE_CURRENT_LIST_DIR}/${txt_file}" > "${CMAKE_CURRENT_BINARY_DIR}/${hdr_file}"
        DEPENDS "${txt_file}"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "so_rules: Building ${hdr_file}"
    )
    include_directories(${CMAKE_CURRENT_BINARY_DIR})

endmacro (create_txt_header)

# Use this macro to create hex files
macro (create_pro_header txt_file hdr_file)

    add_custom_command( OUTPUT ${hdr_file}
        COMMAND
            "${SNORT_EXECUTABLE}" --rule-to-hex < "${CMAKE_CURRENT_LIST_DIR}/${txt_file}" > "${CMAKE_CURRENT_BINARY_DIR}/${hdr_file}"
        DEPENDS "${txt_file}"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "so_rules: Building ${hdr_file}"
    )
    include_directories(${CMAKE_CURRENT_BINARY_DIR})
endmacro (create_pro_header)


create_txt_header(sid_18758.txt sid_18758.h)
add_example_library(18758 so_rules sid_18758.cc sid_18758.h)


# if we had a .pro file name 187589.pro and a source file names sid_18759.cc
#create_txt_header(187589.pro 187589.h)
#add_example_library(187589 so_rules 187589.cc 187589.h)
