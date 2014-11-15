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


set (PROTOCOL_HEADERS
    arp.h
    eapol.h
    eth.h
    icmp4.h
    icmp6.h
    ip.h
    ipv4.h
    ipv4_options.h
    ipv6.h
    gre.h
    layer.h
    linux_sll.h
    mpls.h
    packet.h
    packet_manager.h
    protocol_ids.h
    tcp.h
    tcp_options.h
    teredo.h
    token_ring.h
    udp.h
    wlan.h
    vlan.h
)

add_library (protocols STATIC
    ${PROTOCOL_HEADERS}
    layer.cc
    packet.cc
    ip.cc
    ipv4_options.cc
    tcp_options.cc
    packet_manager.cc
)

install (FILES ${PROTOCOL_HEADERS}
    DESTINATION "${INCLUDE_INSTALL_PATH}/protocols"
)
