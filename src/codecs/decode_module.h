/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

// decode_module.h author Russ Combs <rucombs@cisco.com>

#ifndef DECODE_MODULE
#define DECODE_MODULE

#include "framework/module.h"

#define GID_DECODE 116

#define DECODE_NOT_IPV4_DGRAM                 1
#define DECODE_IPV4_INVALID_HEADER_LEN        2
#define DECODE_IPV4_DGRAM_LT_IPHDR            3
#define DECODE_IPV4OPT_BADLEN                 4
#define DECODE_IPV4OPT_TRUNCATED              5
#define DECODE_IPV4_DGRAM_GT_CAPLEN           6

#define DECODE_TCP_DGRAM_LT_TCPHDR            45
#define DECODE_TCP_INVALID_OFFSET             46
#define DECODE_TCP_LARGE_OFFSET               47

#define DECODE_TCPOPT_BADLEN                  54
#define DECODE_TCPOPT_TRUNCATED               55
#define DECODE_TCPOPT_TTCP                    56
#define DECODE_TCPOPT_OBSOLETE                57
#define DECODE_TCPOPT_EXPERIMENTAL            58
#define DECODE_TCPOPT_WSCALE_INVALID          59

#define DECODE_UDP_DGRAM_LT_UDPHDR            95
#define DECODE_UDP_DGRAM_INVALID_LENGTH       96
#define DECODE_UDP_DGRAM_SHORT_PACKET         97
#define DECODE_UDP_DGRAM_LONG_PACKET          98

#define DECODE_ICMP_DGRAM_LT_ICMPHDR          105
#define DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR     106
#define DECODE_ICMP_DGRAM_LT_ADDRHDR          107

#define DECODE_ARP_TRUNCATED                  109
#define DECODE_EAPOL_TRUNCATED                110
#define DECODE_EAPKEY_TRUNCATED               111
#define DECODE_EAP_TRUNCATED                  112

#define DECODE_BAD_PPPOE                      120
#define DECODE_BAD_VLAN                       130
#define DECODE_BAD_VLAN_ETHLLC                131
#define DECODE_BAD_VLAN_OTHER                 132
#define DECODE_BAD_80211_ETHLLC               133
#define DECODE_BAD_80211_OTHER                134

#define DECODE_BAD_TRH                        140
#define DECODE_BAD_TR_ETHLLC                  141
#define DECODE_BAD_TR_MR_LEN                  142
#define DECODE_BAD_TRHMR                      143

#define DECODE_BAD_TRAFFIC_LOOPBACK           150
#define DECODE_BAD_TRAFFIC_SAME_SRCDST        151

#define DECODE_GRE_DGRAM_LT_GREHDR            160
#define DECODE_GRE_MULTIPLE_ENCAPSULATION     161
#define DECODE_GRE_INVALID_VERSION            162
#define DECODE_GRE_INVALID_HEADER             163
#define DECODE_GRE_V1_INVALID_HEADER          164
#define DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR    165

#define DECODE_BAD_MPLS                       170
#define DECODE_BAD_MPLS_LABEL0                171
#define DECODE_BAD_MPLS_LABEL1                172
#define DECODE_BAD_MPLS_LABEL2                173
#define DECODE_BAD_MPLS_LABEL3                174
#define DECODE_MPLS_RESERVED_LABEL            175
#define DECODE_MPLS_LABEL_STACK               176

#define DECODE_ICMP_ORIG_IP_TRUNCATED         250
#define DECODE_ICMP_ORIG_IP_VER_MISMATCH      251
#define DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP     252
#define DECODE_ICMP_ORIG_PAYLOAD_LT_64        253
#define DECODE_ICMP_ORIG_PAYLOAD_GT_576       254
#define DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET   255

#define DECODE_IPV6_MIN_TTL                   270
#define DECODE_IPV6_IS_NOT                    271
#define DECODE_IPV6_TRUNCATED_EXT             272
#define DECODE_IPV6_TRUNCATED                 273
#define DECODE_IPV6_DGRAM_LT_IPHDR            274
#define DECODE_IPV6_DGRAM_GT_CAPLEN           275
#define DECODE_IPV6_DST_ZERO                  276
#define DECODE_IPV6_SRC_MULTICAST             277
#define DECODE_IPV6_DST_RESERVED_MULTICAST    278
#define DECODE_IPV6_BAD_OPT_TYPE              279
#define DECODE_IPV6_BAD_MULTICAST_SCOPE       280
#define DECODE_IPV6_BAD_NEXT_HEADER           281
#define DECODE_IPV6_ROUTE_AND_HOPBYHOP        282
#define DECODE_IPV6_TWO_ROUTE_HEADERS         283

#define DECODE_ICMPV6_TOO_BIG_BAD_MTU         285
#define DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE    286
#define DECODE_ICMPV6_SOLICITATION_BAD_CODE   287
#define DECODE_ICMPV6_ADVERT_BAD_CODE         288
#define DECODE_ICMPV6_SOLICITATION_BAD_RESERVED     289
#define DECODE_ICMPV6_ADVERT_BAD_REACHABLE    290

#define DECODE_IPV6_TUNNELED_IPV4_TRUNCATED   291
#define DECODE_IPV6_DSTOPTS_WITH_ROUTING      292
#define DECODE_IP_MULTIPLE_ENCAPSULATION      293

#define DECODE_ESP_HEADER_TRUNC               294
#define DECODE_IPV6_BAD_OPT_LEN               295
#define DECODE_IPV6_UNORDERED_EXTENSIONS      296

#define DECODE_GTP_MULTIPLE_ENCAPSULATION     297
#define DECODE_GTP_BAD_LEN                    298

//-----------------------------------------------------
// remember to add rules to preproc_rules/decoder.rules
// add the new decoder rules to the following enum.

#define DECODE_START_INDEX                    400

enum {
    DECODE_TCP_XMAS = DECODE_START_INDEX,
    DECODE_TCP_NMAP_XMAS,
    DECODE_DOS_NAPTHA,
    DECODE_SYN_TO_MULTICAST,
    DECODE_ZERO_TTL,
    DECODE_BAD_FRAGBITS,
    DECODE_UDP_IPV6_ZERO_CHECKSUM,
    DECODE_IP4_LEN_OFFSET,
    DECODE_IP4_SRC_THIS_NET,
    DECODE_IP4_DST_THIS_NET,
    DECODE_IP4_SRC_MULTICAST,
    DECODE_IP4_SRC_RESERVED,
    DECODE_IP4_DST_RESERVED,
    DECODE_IP4_SRC_BROADCAST,
    DECODE_IP4_DST_BROADCAST,
    DECODE_ICMP4_DST_MULTICAST,
    DECODE_ICMP4_DST_BROADCAST,
    DECODE_ICMP4_TYPE_OTHER = 418,
    DECODE_TCP_BAD_URP,
    DECODE_TCP_SYN_FIN,
    DECODE_TCP_SYN_RST,
    DECODE_TCP_MUST_ACK,
    DECODE_TCP_NO_SYN_ACK_RST,
    DECODE_ETH_HDR_TRUNC,
    DECODE_IP4_HDR_TRUNC,
    DECODE_ICMP4_HDR_TRUNC,
    DECODE_ICMP6_HDR_TRUNC,
    DECODE_IP4_MIN_TTL,
    DECODE_IP6_ZERO_HOP_LIMIT,
    DECODE_IP4_DF_OFFSET,
    DECODE_ICMP6_TYPE_OTHER,
    DECODE_ICMP6_DST_MULTICAST,
    DECODE_TCP_SHAFT_SYNFLOOD,
    DECODE_ICMP_PING_NMAP,
    DECODE_ICMP_ICMPENUM,
    DECODE_ICMP_REDIRECT_HOST,
    DECODE_ICMP_REDIRECT_NET,
    DECODE_ICMP_TRACEROUTE_IPOPTS,
    DECODE_ICMP_SOURCE_QUENCH,
    DECODE_ICMP_BROADSCAN_SMURF_SCANNER,
    DECODE_ICMP_DST_UNREACH_ADMIN_PROHIBITED,
    DECODE_ICMP_DST_UNREACH_DST_HOST_PROHIBITED,
    DECODE_ICMP_DST_UNREACH_DST_NET_PROHIBITED,
    DECODE_IP_OPTION_SET,
    DECODE_UDP_LARGE_PACKET,
    DECODE_TCP_PORT_ZERO,
    DECODE_UDP_PORT_ZERO,
    DECODE_IP_RESERVED_FRAG_BIT,
    DECODE_IP_UNASSIGNED_PROTO,
    DECODE_IP_BAD_PROTO,
    DECODE_ICMP_PATH_MTU_DOS,
    DECODE_ICMP_DOS_ATTEMPT,
    DECODE_IPV6_ISATAP_SPOOF,
    DECODE_PGM_NAK_OVERFLOW,
    DECODE_IGMP_OPTIONS_DOS,
    DECODE_IP6_EXCESS_EXT_HDR,
    DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE,
    DECODE_IPV6_BAD_FRAG_PKT,
    DECODE_ZERO_LENGTH_FRAG,
    DECODE_ICMPV6_NODE_INFO_BAD_CODE,
    DECODE_IPV6_ROUTE_ZERO,
    DECODE_ERSPAN_HDR_VERSION_MISMATCH,
    DECODE_ERSPAN2_DGRAM_LT_HDR,
    DECODE_ERSPAN3_DGRAM_LT_HDR,
    DECODE_INDEX_MAX
};


//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class DecodeModule : public Module
{
public:
    DecodeModule();
    bool set(const char*, Value&, SnortConfig*);

    unsigned get_gid() const
    { return GID_DECODE; };
};

#endif

