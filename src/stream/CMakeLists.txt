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


add_subdirectory(base)
add_subdirectory(ip)
add_subdirectory(icmp)
add_subdirectory(tcp)
add_subdirectory(udp)

set (STREAM_INCLUDES
    stream_api.h
    stream_splitter.h
)

add_library( stream STATIC
    flush_bucket.cc
    flush_bucket.h
    stream.h
    stream_api.cc
    stream_inspectors.cc
    stream_inspectors.h
    stream_splitter.cc
)

target_link_libraries( stream
    stream_base
    stream_ip
    stream_icmp
    stream_tcp
    stream_udp
    protocols
)

install (FILES ${STREAM_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/stream"
)
