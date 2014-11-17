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

set (DETECTION_INCLUDES
    detection_defines.h
    detection_options.h
    rule_option_types.h
    rules.h
    signature.h
    treenodes.h
)

add_library (detection STATIC
    ${DETECTION_INCLUDES}
    detect.cc 
    detect.h 
    detection_options.cc
    detection_util.cc 
    detection_util.h 
    fpcreate.cc 
    fpcreate.h 
    fpdetect.cc 
    fpdetect.h 
    pcrm.cc 
    pcrm.h 
    sfrim.cc 
    sfrim.h 
    signature.cc 
    treenodes.cc
    tag.cc 
    tag.h 
)

target_link_libraries( detection
    framework
    managers
)

install(FILES ${DETECTION_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/detection"
)
