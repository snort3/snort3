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

include_directories (${PCAP_INCLUDE_DIR})


if (STATIC_CODECS)
    set (PLUGIN_LIST
        cd_eth.cc
        cd_linux_sll.cc
        cd_null.cc
        cd_ppp.cc
        cd_raw4.cc
        cd_raw6.cc
        cd_slip.cc
        cd_wlan.cc
#        root_fddi.cc
#        root_i4lrawip.cc
#        root_oldpflog.cc
#        root_enc.cc
#        root_pflog.cc
#        root_pppserial.cc
#        root_chdlc.cc
#        root_i4lciscoip.cc
#        prot_ipx.cc
#        prot_eap.cc
    )


else (STATIC_CODECS)
    add_shared_library (cd_eth codecs cd_eth.cc)
    add_shared_library (cd_linux_sll codecs cd_linux_sll.cc)
    add_shared_library (cd_null codecs cd_null.cc)
    add_shared_library (cd_ppp codecs cd_ppp.cc)
    add_shared_library (cd_raw4 codecs cd_raw4.cc)
    add_shared_library (cd_raw6 codecs cd_raw6.cc)
    add_shared_library (cd_slip codecs cd_slip.cc)
    add_shared_library (cd_wlan codecs cd_wlan.cc)

endif (STATIC_CODECS)


if (STATIC_CODECS)
    add_library(root_codecs STATIC
        ${PLUGIN_LIST}
        ${PCAP_INCLUDE_DIR}/pcap.h  # rebuild if a new libpcap is installed
    )

endif (STATIC_CODECS)
