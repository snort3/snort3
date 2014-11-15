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


set (FLOW_INCLUDES
    flow.h
    flow_key.h
)

add_library ( flow STATIC
    ${FLOW_INCLUDES}
    flow.cc 
    flow_key.cc 
    flow_cache.cc 
    flow_cache.h 
    expect_cache.cc 
    expect_cache.h 
    flow_control.cc 
    flow_control.h 
    session.h
)

set_default_visibility_compile_flag(flow)

target_link_libraries(flow
    protocols
)

install(FILES ${FLOW_INCLUDES}
    DESTINATION ${INCLUDE_INSTALL_PATH}/flow
)
