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


include_directories(${PROJECT_SOURCE_DIR}/src/loggers)

add_executable( u2boat
    u2boat.cc
    u2boat.h
)

target_link_libraries( u2boat
    ${PCAP_LIBRARIES}
)

#add_compile_flags(u2boat ${AM_CFLAGS})

set( AM_CXXFLAGS ${AM_CXXFLAGS} ${EXTRA_INCL}]})

install (TARGETS u2boat
    RUNTIME DESTINATION bin
)

install(FILES README.u2boat
    DESTINATION ${SNORT_DATA_DIR}
)

