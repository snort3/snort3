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

if(STATIC_CODECS)
    set(PLUGIN_LIST
        cd_gtp.cc
        cd_icmp4_ip.cc
        cd_icmp6_ip.cc
        cd_llc.cc
        cd_teredo.cc
    )

else(STATIC_CODECS)
    add_shared_library(cd_gtp codecs cd_gtp.cc)
    add_shared_library(cd_teredo codecs cd_teredo.cc)
    add_shared_library(cd_icmp4_ip codecs cd_icmp4_ip.cc)
    add_shared_library(cd_icmp6_ip codecs cd_icmp6_ip.cc)
    add_shared_library(cd_llc codecs cd_llc.cc)

endif(STATIC_CODECS)

add_library( misc_codecs STATIC
    cd_default.cc
    ${PLUGIN_LIST}
)

target_link_libraries( misc_codecs
    protocols
)
