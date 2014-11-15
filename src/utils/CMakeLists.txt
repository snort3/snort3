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


find_package(Threads REQUIRED)

add_definitions(" -std=c++11  -DHAVE_PTHREADS  ")

if ( BUILD_SNPRINTF )
    SET (SNPRINTF_SOURCES
        snprintf.cc 
        snprintf.h c
        defs.h
    )
endif ( BUILD_SNPRINTF )


set( UTIL_INCLUDES
    bitop.h
    bitop_funcs.h
    dnet_header.h
    segment_mem.h
    sflsq.h
    sfmemcap.h
    sfportobject.h
    snort_bounds.h
    stats.h
    util.h
)

ADD_LIBRARY( utils STATIC
    ${UTIL_INCLUDES}
    ${SNPRINTF_SOURCES}
    boyer_moore.cc 
    boyer_moore.h
    dyn_array.cc
    dyn_array.h
    ring.h 
    ring_logic.h
    segment_mem.cc 
    sf_email_attach_decode.cc 
    sf_email_attach_decode.h
    sf_base64decode.cc 
    sf_base64decode.h
    sflsq.cc 
    sfmemcap.cc 
    sfportobject.cc 
    sfsnprintfappend.cc 
    sfsnprintfappend.h
    strvec.cc 
    strvec.h
    stats.cc 
    util.cc 
    util_jsnorm.cc 
    util_jsnorm.h
    util_math.cc 
    util_math.h
    util_net.cc 
    util_net.h
    util_str.cc 
    util_str.h
    util_utf.cc 
    util_utf.h
    util_unfold.cc 
    util_unfold.h
)

target_link_libraries(utils
    log
)

install (FILES ${UTIL_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/utils"
)
