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


set ( ACTIONS_INCLUDES
    actions.h
)

set (IPS_ACTION_SOURCES
    actions.cc
    ips_actions.cc
    ips_actions.h
    act_replace.cc
    act_replace.h
)

set( PLUGIN_LIST
    act_react.cc
    act_reject.cc
    )

if (STATIC_IPS_ACTIONS)
    add_library ( ips_actions STATIC
        ${IPS_ACTION_SOURCES}
        ${PLUGIN_LIST}
    )

else (STATIC_IPS_ACTIONS)

    add_library ( ips_actions STATIC
        ${IPS_ACTION_SOURCES}
    )

    add_shared_library(act_react actions act_react.cc)
    add_shared_library(act_reject actions act_reject.cc)

endif (STATIC_IPS_ACTIONS)

install (FILES ${ACTIONS_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/actions"
)

