//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// protocol_ids.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_PROTOCOL_IDS_H
#define PROTOCOLS_PROTOCOL_IDS_H

/*****************************************************************
 *****  NOTE:   Protocols are only included in this file when ****
 *****          their IDs are needed throughout multiple      ****
 *****          files.  If a protocol ID is only needed in    ****
 *****          one file, define that number as a             ****
 *****          static const uint16_t ID_NAME = ZZZZ          ****
 *****          in the specific file.                         ****
 ****************************************************************/

/*
 *  PROTOCOL ID'S By Range
 *   0    (0x0000) -   255  (0x00FF)  --> IP protocols
 *   256  (0x0100) -  1535  (0x05FF)  --> protocols without IDs (teredo, gtp)
 *  1536  (0x6000) -  65536 (0xFFFF)  --> Ethertypes
 */

/*
 * Below is a partial list of protocol numbers for the IP protocols.
 *  Defined at:
 * http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 */
constexpr uint16_t IPPROTO_ID_HOPOPTS = 0;
constexpr uint16_t IPPROTO_ID_ICMPV4 = 1;
constexpr uint16_t IPPROTO_ID_IPIP = 4;
constexpr uint16_t IPPROTO_ID_TCP = 6;
constexpr uint16_t IPPROTO_ID_UDP = 17;
constexpr uint16_t IPPROTO_ID_IPV6 = 41;
constexpr uint16_t IPPROTO_ID_ROUTING = 43;
constexpr uint16_t IPPROTO_ID_FRAGMENT = 44;
constexpr uint16_t IPPROTO_ID_GRE = 47;
constexpr uint16_t IPPROTO_ID_ESP = 50;
constexpr uint16_t IPPROTO_ID_AUTH = 51; // RFC 4302
constexpr uint16_t IPPROTO_ID_MOBILITY = 55;
constexpr uint16_t IPPROTO_ID_ICMPV6 = 58;
constexpr uint16_t IPPROTO_ID_NONEXT = 59;
constexpr uint16_t IPPROTO_ID_DSTOPTS = 60;
constexpr uint16_t IPPROTO_ID_RESERVED = 255; // == 0xFF

/* Last updated 2/4/2015.
   Source: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml */
constexpr uint16_t MIN_UNASSIGNED_IP_PROTO = 143;

/*
 *  Undefined Protocol!
 */
constexpr uint16_t FINISHED_DECODE = 0x0100;  // Indicates Codecs have succesfully decoded packet
constexpr uint16_t PROTO_TEREDO = 0x0101;
constexpr uint16_t PROTO_GTP = 0x0102;
constexpr uint16_t PROTO_IP_EMBEDDED_IN_ICMP4 = 0x0103;
constexpr uint16_t PROTO_IP_EMBEDDED_IN_ICMP6 = 0x0104;
constexpr uint16_t PROTO_ETHERNET_802_3 = 0x0105;
constexpr uint16_t PROTO_ETHERNET_802_11 = 0x0106;
constexpr uint16_t PROTO_ETHERNET_LLC = 0x0107;

/*
 * Below is a partial list of ethertypes.
 *  Defined at:
 *
 *  Defined at:
 * http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
 */
constexpr uint16_t ETHERTYPE_TRANS_ETHER_BRIDGING = 0x6558;
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_REVARP = 0x8035;
constexpr uint16_t ETHERTYPE_ARP = 0x0806;
constexpr uint16_t ETHERTYPE_8021Q = 0x8100;
constexpr uint16_t ETHERTYPE_IPX = 0x8137;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86dd;
constexpr uint16_t ETHERTYPE_PPP = 0x880B;
constexpr uint16_t ETHERTYPE_EAPOL = 0x888e;
constexpr uint16_t ETHERTYPE_FPATH = 0x8903;

static inline bool is_ip6_extension(const uint8_t proto)
{
    switch (proto)
    {
    case IPPROTO_ID_HOPOPTS:
    case IPPROTO_ID_DSTOPTS:
    case IPPROTO_ID_ROUTING:
    case IPPROTO_ID_FRAGMENT:
    case IPPROTO_ID_AUTH:
    case IPPROTO_ID_ESP:
    case IPPROTO_ID_MOBILITY:
    case IPPROTO_ID_NONEXT:
        return true;
    default:
        return false;
    }
}

#endif

