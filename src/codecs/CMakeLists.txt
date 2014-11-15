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

add_subdirectory(root)
add_subdirectory(link)
add_subdirectory(ip)
add_subdirectory(misc)

set(CODEC_INCLUDES
    codec_module.h
    codec_events.h
)

add_library( codecs STATIC
    ${CODEC_INCLUDES}
    codec_api.h
    codec_api.cc
    template.cc   # for development purposes.  Keep the template up to date
)


if (STATIC_CODECS)
    set (CODEC_PLUGIN_LIBRARIES
        link_codecs
        root_codecs
    )
endif(STATIC_CODECS)

target_link_libraries( codecs
    ${CODEC_PLUGIN_LIBRARIES}
    ip_codecs
    misc_codecs
    protocols
    sfip
    framework
    main
)


install (FILES ${CODEC_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/codecs"
)
