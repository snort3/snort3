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


set (INCLUDES
    thread.h
    snort_debug.h
    snort_types.h
    snort.h
    snort_config.h
    policy.h
)

add_library (main STATIC
    analyzer.h
    analyzer.cc 
    build.h
    help.cc
    help.h
    modules.cc
    modules.h
    policy.cc
    shell.h
    shell.cc
    snort.h
    snort.cc
    snort_debug.cc
    snort_config.cc
    snort_module.h
    snort_module.cc
    thread.cc 
	${INCLUDES}
)


target_link_libraries(main
    time
    codecs
    detection
    packet_io
)

install (FILES ${INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/main"
)
