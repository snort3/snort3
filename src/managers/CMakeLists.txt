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


include_directories(${LUAJIT_INCLUDE_DIR})

set (LUA_INCLUDES
    snort_config.lua
    snort_plugin.lua
)

add_library( managers
    action_manager.h
    action_manager.cc
    data_manager.h
    data_manager.cc
    codec_manager.h
    codec_manager.cc
    event_manager.cc
    event_manager.h
    inspector_manager.cc
    inspector_manager.h
    ips_manager.cc
    ips_manager.h
    module_manager.cc
    module_manager.h
    mpse_manager.cc
    mpse_manager.h
    plugin_manager.cc
    plugin_manager.h
    script_manager.cc
    script_manager.h
    so_manager.cc
    so_manager.h
)

target_link_libraries(managers
    framework
    helpers
    loggers
    ips_options
    network_inspectors
    service_inspectors
    search_engines
    parser
    codecs
    ips_actions
)

install (FILES ${LUA_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/lua"
)
