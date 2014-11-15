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
    set( PLUGIN_SOURCES
        cd_arp.cc
        cd_eapol.cc
        cd_erspan2.cc
        cd_erspan3.cc
        cd_mpls.cc
        cd_ppp_encap.cc
        cd_pppoe.cc
        cd_trans_bridge.cc
        cd_vlan.cc
    )


else(STATIC_CODECS)
    add_shared_library(cd_arp codecs cd_arp.cc)
    add_shared_library(cd_erspan2 codecs cd_erspan2.cc)
    add_shared_library(cd_erspan3 codecs cd_erspan3.cc)
    add_shared_library(cd_mpls codecs cd_mpls.cc)
    add_shared_library(cd_ppp_encap codecs cd_ppp_encap.cc)
    add_shared_library(cd_pppoe codecs cd_pppoe.cc)
    add_shared_library(cd_trans_bridge codecs cd_trans_bridge.cc)
    add_shared_library(cd_vlan codecs cd_vlan.cc)
    add_shared_library(cd_eapol codecs cd_eapol.cc)

endif(STATIC_CODECS)



# NOTE: if any static libraries need to built, this extra if()
#       MUST be removed.  It is here because cmake sends out
#       a warning if no files exist in the link codecs library

if(STATIC_CODECS)
    add_library( link_codecs STATIC
        ${PLUGIN_SOURCES}
    )


    target_link_libraries( link_codecs
        events
        managers
    )

endif(STATIC_CODECS)
