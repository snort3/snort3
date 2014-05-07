/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// packet_manager.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include "codec_api.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"

// root decoders
extern const BaseApi* cd_eth;
extern const BaseApi* cd_raw4;
extern const BaseApi* cd_raw6;
extern const BaseApi* cd_null_root;


#ifndef NO_NON_ETHER_DECODER

#endif

// decoders
extern const BaseApi* cd_ipv4;
extern const BaseApi* cd_ipv6;
extern const BaseApi* cd_icmp4;
extern const BaseApi* cd_icmp6;
extern const BaseApi* cd_tcp;
extern const BaseApi* cd_udp;
extern const BaseApi* cd_esp;
extern const BaseApi* cd_null;

#ifdef STATIC_DECODERS
extern const BaseApi* cd_ah;
extern const BaseApi* cd_arp;
extern const BaseApi* cd_dstopts;
extern const BaseApi* cd_erspan2;
extern const BaseApi* cd_erspan3; 
extern const BaseApi* cd_ethloopback; 
extern const BaseApi* cd_frag; 
extern const BaseApi* cd_gre;
extern const BaseApi* cd_gtp;
extern const BaseApi* cd_hopopts;
extern const BaseApi* cd_igmp;
extern const BaseApi* cd_mpls;
extern const BaseApi* cd_no_next;
extern const BaseApi* cd_pgm;
extern const BaseApi* cd_pppencap;
extern const BaseApi* cd_pppoe;
extern const BaseApi* cd_routing;
extern const BaseApi* cd_swipe;
extern const BaseApi* cd_teredo;
extern const BaseApi* cd_transbridge;
extern const BaseApi* cd_vlan;

#ifndef NO_NON_ETHER_DECODER
extern const BaseApi* cd_eapol;

#endif

#endif


const BaseApi* codecs[] =
{
    cd_eth,
    cd_raw4,
    cd_raw6,
    cd_null_root,

#ifndef NO_NON_ETHER_DECODER

#endif

    // non root codeccs
    cd_ipv4,
    cd_ipv6,
    cd_icmp4,
    cd_icmp6,
    cd_tcp,
    cd_udp,
    cd_esp,
    cd_null,

#ifdef STATIC_DECODERS
    cd_ah,
    cd_arp,
    cd_dstopts,
    cd_erspan2,
    cd_erspan3,
    cd_ethloopback,
    cd_frag,
    cd_gre,
    cd_gtp,
    cd_hopopts,
    cd_igmp,
    cd_mpls,
    cd_no_next,
    cd_pgm,
    cd_pppencap,
    cd_pppoe,
    cd_routing,
    cd_swipe,
    cd_teredo,
    cd_transbridge,
    cd_vlan,

#ifndef NO_NON_ETHER_DECODER
    cd_eapol,
#endif

#endif

    nullptr
};

