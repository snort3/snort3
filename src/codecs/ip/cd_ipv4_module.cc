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

// cd_ipv4_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/ip/cd_ipv4_module.h"


static const Parameter ipv4_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


// rules which will loaded into snort. 
// You can now reference these rules by calling a codec_event
// in your main codec's functions
static const RuleMap ipv4_rules[] =
{
    { DECODE_NOT_IPV4_DGRAM, "(" CD_IPV4_NAME ") Not IPv4 datagram" },
    { DECODE_IPV4_INVALID_HEADER_LEN, "(" CD_IPV4_NAME ") hlen < IP_HEADER_LEN" },
    { DECODE_IPV4_DGRAM_LT_IPHDR, "(" CD_IPV4_NAME ") IP dgm len < IP Hdr len" },
    { DECODE_IPV4OPT_BADLEN, "(" CD_IPV4_NAME ") Ipv4 Options found with bad lengths" },
    { DECODE_IPV4OPT_TRUNCATED, "(" CD_IPV4_NAME ") Truncated Ipv4 Options" },
    { DECODE_IPV4_DGRAM_GT_CAPLEN, "(" CD_IPV4_NAME ") IP dgm len > captured len" },
    { DECODE_ZERO_TTL, "(" CD_IPV4_NAME ") IPV4 packet with zero TTL" },
    { DECODE_BAD_FRAGBITS, "(" CD_IPV4_NAME ") IPV4 packet with bad frag bits (Both MF and DF set)" },
    { DECODE_IP4_LEN_OFFSET, "(" CD_IPV4_NAME ") IPV4 packet frag offset + length exceed maximum" },
    { DECODE_IP4_SRC_THIS_NET, "(" CD_IPV4_NAME ") IPV4 packet from 'current net' source address" },
    { DECODE_IP4_DST_THIS_NET, "(" CD_IPV4_NAME ") IPV4 packet to 'current net' dest address" },
    { DECODE_IP4_SRC_MULTICAST, "(" CD_IPV4_NAME ") IPV4 packet from multicast source address" },
    { DECODE_IP4_SRC_RESERVED, "(" CD_IPV4_NAME ") IPV4 packet from reserved source address" },
    { DECODE_IP4_DST_RESERVED, "(" CD_IPV4_NAME ") IPV4 packet to reserved dest address" },
    { DECODE_IP4_SRC_BROADCAST, "(" CD_IPV4_NAME ") IPV4 packet from broadcast source address" },
    { DECODE_IP4_DST_BROADCAST, "(" CD_IPV4_NAME ") IPV4 packet to broadcast dest address" },
    { DECODE_IP4_MIN_TTL, "(" CD_IPV4_NAME ") IPV4 packet below TTL limit" },
    { DECODE_IP4_DF_OFFSET, "(" CD_IPV4_NAME ") IPV4 packet both DF and offset set" },
    { DECODE_IP_RESERVED_FRAG_BIT, "(decode) BAD-TRAFFIC IP reserved bit set" },
    { DECODE_IP_UNASSIGNED_PROTO, "(decode) BAD-TRAFFIC Unassigned/Reserved IP protocol" },
    { DECODE_IP_BAD_PROTO, "(decode) BAD-TRAFFIC Bad IP protocol" },
    { DECODE_IP_OPTION_SET, "(decode) MISC IP option set" },
    { DECODE_IP_MULTIPLE_ENCAPSULATION, "(decode) Two or more IP (v4 and/or v6) encapsulation layers present" },
    { DECODE_ZERO_LENGTH_FRAG, "(decode) fragment with zero length" },
    { DECODE_IP4_HDR_TRUNC, "(decode) truncated IP4 header" },
    { DECODE_BAD_TRAFFIC_LOOPBACK, "(snort decoder) Bad Traffic Loopback IP" },
    { DECODE_BAD_TRAFFIC_SAME_SRCDST, "(snort decoder) Bad Traffic Same Src/Dst IP" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

Ipv4Module::Ipv4Module() : DecodeModule(CD_IPV4_NAME, ipv4_params, ipv4_rules)
{ }

bool Ipv4Module::set(const char*, Value&, SnortConfig*)
{
    return true;
}


