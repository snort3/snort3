//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// decode_data.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef FRAMEWORK_DECODE_DATA_H
#define FRAMEWORK_DECODE_DATA_H

// Captures decode information from Codecs.

#include "protocols/ip.h"
#include "protocols/mpls.h"

namespace snort
{
namespace tcp
{
struct TCPHdr;
}
namespace udp
{
struct UDPHdr;
}
namespace icmp
{
struct ICMPHdr;
}
}

/* NOTE: if A protocol is added, update DecodeFlags! */
enum class PktType : std::uint8_t
{
    NONE, IP, TCP, UDP, ICMP, USER, FILE, PDU, MAX
};

enum class LRUType : std::uint8_t 
{
    NONE = static_cast<std::uint8_t>(PktType::NONE),
    IP = static_cast<std::uint8_t>(PktType::IP),
    TCP = static_cast<std::uint8_t>(PktType::TCP),
    UDP = static_cast<std::uint8_t>(PktType::UDP),
    ICMP = static_cast<std::uint8_t>(PktType::ICMP),
    USER = static_cast<std::uint8_t>(PktType::USER),
    FILE = static_cast<std::uint8_t>(PktType::FILE),
    PDU = static_cast<std::uint8_t>(PktType::PDU),
    ALLOW_LIST,
    MAX
};

// the first several of these bits must map to PktType
// eg PROTO_BIT__IP == BIT(PktType::IP), etc.
#define PROTO_BIT__NONE             0x000000
#define PROTO_BIT__IP               0x000001
#define PROTO_BIT__TCP              0x000002
#define PROTO_BIT__UDP              0x000004
#define PROTO_BIT__ICMP             0x000008
#define PROTO_BIT__USER             0x000010
#define PROTO_BIT__FILE             0x000020
#define PROTO_BIT__PDU              0x000040
#define PROTO_BIT__TEREDO           0x000080
#define PROTO_BIT__GTP              0x000100
#define PROTO_BIT__MPLS             0x000200
#define PROTO_BIT__VLAN             0x000400
#define PROTO_BIT__ETH              0x000800
#define PROTO_BIT__TCP_EMBED_ICMP   0x001000
#define PROTO_BIT__UDP_EMBED_ICMP   0x002000
#define PROTO_BIT__ICMP_EMBED_ICMP  0x004000
#define PROTO_BIT__ICMP_EMBED_OTHER 0x008000
#define PROTO_BIT__IP6_EXT          0x010000
#define PROTO_BIT__CISCO_META_DATA  0x020000
#define PROTO_BIT__VXLAN            0x040000
#define PROTO_BIT__UDP_TUNNELED     0x080000
#define PROTO_BIT__OTHER            0x100000
#define PROTO_BIT__GENEVE           0x200000
#define PROTO_BIT__ARP              0x400000
#define PROTO_BIT__ALL              0x7FFFFF

#define PROTO_BIT__ICMP_EMBED \
    (PROTO_BIT__TCP_EMBED_ICMP | PROTO_BIT__UDP_EMBED_ICMP | \
    PROTO_BIT__ICMP_EMBED_ICMP | PROTO_BIT__ICMP_EMBED_OTHER)

#define PROTO_BIT__ANY_IP   (PROTO_BIT__IP | PROTO_BIT__TCP | PROTO_BIT__UDP | PROTO_BIT__ICMP)
#define PROTO_BIT__ANY_PDU  (PROTO_BIT__TCP | PROTO_BIT__UDP | PROTO_BIT__PDU)
#define PROTO_BIT__ANY_SSN  (PROTO_BIT__ANY_IP | PROTO_BIT__PDU | PROTO_BIT__FILE | PROTO_BIT__USER)
#define PROTO_BIT__ANY_TYPE (PROTO_BIT__ANY_SSN | PROTO_BIT__ARP)

enum DecodeFlags : std::uint32_t
{
    DECODE_ERR_CKSUM_IP =   0x00000001,  // error flags
    DECODE_ERR_CKSUM_TCP =  0x00000002,
    DECODE_ERR_CKSUM_UDP =  0x00000004,
    DECODE_ERR_CKSUM_ICMP = 0x00000008,
    DECODE_ERR_BAD_TTL =    0x00000010,

    DECODE_ERR_CKSUM_ALL = ( DECODE_ERR_CKSUM_IP | DECODE_ERR_CKSUM_TCP |
        DECODE_ERR_CKSUM_UDP | DECODE_ERR_CKSUM_ICMP ),

    DECODE_PKT_TRUST =      0x00000020,  // trust this packet
    DECODE_FRAG =           0x00000040,  // ip - fragmented packet
    DECODE_MF =             0x00000080,  // ip - more fragments
    DECODE_DF =             0x00000100,  // ip - don't fragment

    // using decode flags in lieu of creating user layer for now
    DECODE_C2S =            0x00000200,  // user - client to server
    DECODE_SOF =            0x00000400,  // user - start of flow
    DECODE_EOF =            0x00000800,  // user - end of flow
    DECODE_GTP =            0x00001000,

    DECODE_TCP_MSS =        0x00002000,
    DECODE_TCP_TS =         0x00004000,
    DECODE_TCP_WS =         0x00008000,

    DECODE_ERR_LEN =        0X00010000,  // received incorrect len from DAQ

    DECODE_ERR_FLAGS = ( DECODE_ERR_CKSUM_ALL | DECODE_ERR_BAD_TTL | DECODE_ERR_LEN ),
};

struct DecodeData
{
    /*
     * these three pointers are each referenced literally
     * dozens if not hundreds of times.  NOTHING else should be added!!
     */
    const snort::tcp::TCPHdr* tcph = nullptr;
    const snort::udp::UDPHdr* udph = nullptr;
    const snort::icmp::ICMPHdr* icmph = nullptr;

    uint16_t sp = 0;    /* source port (TCP/UDP) */
    uint16_t dp = 0;    /* dest port (TCP/UDP) */

    uint32_t decode_flags = 0;
    PktType type = PktType::NONE;

    snort::ip::IpApi ip_api;
    snort::mpls::MplsHdr mplsHdr = {};

    inline void reset()
    {
        tcph = nullptr;
        udph = nullptr;
        icmph = nullptr;
        sp = 0;
        dp = 0;
        decode_flags = 0;
        type = PktType::NONE;
        ip_api.reset();
        mplsHdr = {};
    }

    inline void set_pkt_type(PktType pkt_type)
    { type = pkt_type; }

    inline PktType get_pkt_type() const
    { return type; }
};

#endif

