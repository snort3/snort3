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


set (FRAMEWORK_INCLUDES
    base_api.h
    bits.h
    codec.h
    counts.h
    cursor.h
    decode_data.h
    logger.h
    inspector.h
    ips_action.h
    ips_option.h
    module.h
    mpse.h
    parameter.h
    plug_data.h
    range.h
    so_rule.h
    value.h
)

add_library ( framework STATIC
    ${FRAMEWORK_INCLUDES}
    cursor.cc
    inspector.cc
    ips_option.cc
    parameter.cc
    module.cc
    mpse.cc
    range.cc
    value.cc
)


install (FILES ${FRAMEWORK_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/framework"
)

