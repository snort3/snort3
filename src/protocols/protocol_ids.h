//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include <cassert>
#include <cstdint>
#include <limits>
#include <type_traits>

/*****************************************************************
 *****  NOTE:   Protocols are only included in this file when ****
 *****          their IDs are needed.                         ****
 ****************************************************************/

/*
 *  PROTOCOL ID'S By Range
 *   0    (0x0000) -   255  (0x00FF)  --> IP protocols
 *   256  (0x0100) -  1535  (0x05FF)  --> protocols without IDs (teredo, gtp)
 *  1536  (0x6000) -  65536 (0xFFFF)  --> Ethertypes
 */

//  Convert enum to a value cast to the enum's underlying type.
template<typename E>
inline constexpr typename std::underlying_type<E>::type to_utype(E enumerator)
{
    return static_cast<typename std::underlying_type<E>::type>(enumerator);
}

using ProtocolIndex = uint8_t;

/*
 * Below is a partial list of protocol numbers for the IP protocols.
 *  Defined at:
 * http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 */
enum class IpProtocol : std::uint8_t
{
    IP = 0,
    HOPOPTS = 0,
    ICMPV4 = 1,
    IGMP = 2,
    IPIP = 4,
    TCP = 6,
    UDP = 17,
    IPV6 = 41,
    ROUTING = 43,
    FRAGMENT = 44,
    GRE = 47,
    ESP = 50,
    AUTH = 51, // RFC 4302
    SWIPE = 53,
    MOBILITY = 55,
    ICMPV6 = 58,
    NONEXT = 59,
    DSTOPTS = 60,
    SUN_ND = 77,
    PIM = 103,
    PGM = 113,
    MOBILITY_IPV6 = 135,
    MPLS_IP = 137,
    /* Last updated 3/31/2016.
       Source: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml */
    MIN_UNASSIGNED_IP_PROTO = 143,

    RESERVED = 255,       // == 0xFF
    PORT_SCAN = 255,
    PROTO_NOT_SET = 255,  // Indicates protocol has not been set.
};

//  Values up to 255 MUST be identical to those in IpProtocol.
enum class ProtocolId : std::uint16_t
{
    ETHERTYPE_NOT_SET = 0,
    IP = 0,
    HOPOPTS = 0,
    ICMPV4 = 1,
    IGMP = 2,
    IPIP = 4,
    TCP = 6,
    UDP = 17,
    IPV6 = 41,
    ROUTING = 43,
    FRAGMENT = 44,
    GRE = 47,
    ESP = 50,
    AUTH = 51, // RFC 4302
    SWIPE = 53,
    MOBILITY = 55,
    ICMPV6 = 58,
    NONEXT = 59,
    DSTOPTS = 60,
    SUN_ND = 77,
    PIM = 103,
    PGM = 113,
    MOBILITY_IPV6 = 135,
    MPLS_IP = 137,

    /* Last updated 3/31/2016.
       Source: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml */
    MIN_UNASSIGNED_IP_PROTO = 143,

    RESERVED = 255,       // == 0xFF
    PORT_SCAN = 255,
    PROTO_NOT_SET = 255,  // Indicates protocol has not been set.

    /*
     *  Undefined Protocols!
     */
    FINISHED_DECODE = 0x0100,  // Indicates Codecs have successfully decoded packet
    TEREDO = 0x0101,
    GTP = 0x0102,
    IP_EMBEDDED_IN_ICMP4 = 0x0103,
    IP_EMBEDDED_IN_ICMP6 = 0x0104,
    ETHERNET_802_3 = 0x0105,
    ETHERNET_802_11 = 0x0106,
    ETHERNET_LLC = 0x0107,

    /*
     * Below is a partial list of ethertypes.
     *  Defined at:
     * http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
     */
    ETHERTYPE_MINIMUM = 0x0600,   //  1536 - lowest ethertype value.
    ETHERTYPE_IPV4 = 0x0800,
    ETHERTYPE_ARP = 0x0806,
    ETHERTYPE_ERSPAN_TYPE3 = 0X22EB,
    ETHERTYPE_TRANS_ETHER_BRIDGING = 0x6558,
    ETHERTYPE_REVARP = 0x8035,
    ETHERTYPE_8021Q = 0x8100,
    ETHERTYPE_IPX = 0x8137,
    ETHERTYPE_IPV6 = 0x86DD,
    ETHERTYPE_PPP = 0x880B,
    ETHERTYPE_MPLS_UNICAST = 0x8847,
    ETHERTYPE_MPLS_MULTICAST = 0x8848,
    ETHERTYPE_PPPOE_DISC = 0x8863,
    ETHERTYPE_PPPOE_SESS = 0x8864,
    ETHERTYPE_EAPOL = 0x888E,
    ETHERTYPE_8021AD = 0x88A8,
    ETHERTYPE_ERSPAN_TYPE2 = 0x88BE,
    ETHERTYPE_FPATH = 0x8903,
    ETHERTYPE_CISCO_META = 0x8909,
    ETHERTYPE_QINQ_NS1 = 0x9100,
    ETHERTYPE_QINQ_NS2 = 0x9200,
};

static const auto num_protocol_ids =
    std::numeric_limits<std::underlying_type<ProtocolId>::type>::max() + 1;

inline bool is_ip_protocol(ProtocolId prot_id)
{
    return to_utype(prot_id) <= UINT8_MAX;
}

inline IpProtocol convert_protocolid_to_ipprotocol(const ProtocolId prot_id)
{
    assert(is_ip_protocol(prot_id));

    return IpProtocol(prot_id);
}

inline bool is_ip6_extension(const ProtocolId prot_id)
{
    if (!is_ip_protocol(prot_id))
        return false;

    switch (prot_id)
    {
    case ProtocolId::HOPOPTS:
    case ProtocolId::DSTOPTS:
    case ProtocolId::ROUTING:
    case ProtocolId::FRAGMENT:
    case ProtocolId::AUTH:
    case ProtocolId::ESP:
    case ProtocolId::MOBILITY_IPV6:
    case ProtocolId::NONEXT:
        return true;
    default:
        return false;
    }
}

#endif

