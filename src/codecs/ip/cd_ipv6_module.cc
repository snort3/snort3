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

// cd_ipv6_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/ip/cd_ipv6_module.h"


static const Parameter ipv6_params[] =
{
    { "parameter1", Parameter::PT_BOOL, nullptr, "false",
      "This is a boolean parameter" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


// rules which will loaded into snort. 
// You can now reference these rules by calling a codec_event
// in your main codec's functions
static const RuleMap ipv6_rules[] =
{
    { DECODE_IPV6_MIN_TTL, "(" CD_IPV6_NAME ") IPv6 packet below TTL limit" },
    { DECODE_IPV6_IS_NOT, "(" CD_IPV6_NAME ") IPv6 header claims to not be IPv6" },
    { DECODE_IPV6_TRUNCATED_EXT, "(" CD_IPV6_NAME ") IPV6 truncated extension header" },
    { DECODE_IPV6_TRUNCATED, "(" CD_IPV6_NAME ") IPV6 truncated header" },
    { DECODE_IPV6_DGRAM_LT_IPHDR, "(" CD_IPV6_NAME ") IP dgm len < IP Hdr len" },
    { DECODE_IPV6_DGRAM_GT_CAPLEN, "(" CD_IPV6_NAME ") IP dgm len > captured len" },
    { DECODE_IPV6_DST_ZERO, "(" CD_IPV6_NAME ") IPv6 packet with destination address ::0" },
    { DECODE_IPV6_SRC_MULTICAST, "(" CD_IPV6_NAME ") IPv6 packet with multicast source address" },
    { DECODE_IPV6_DST_RESERVED_MULTICAST, "(" CD_IPV6_NAME ") IPv6 packet with reserved multicast destination address" },
    { DECODE_IPV6_BAD_OPT_TYPE, "(" CD_IPV6_NAME ") IPv6 header includes an undefined option type" },
    { DECODE_IPV6_BAD_MULTICAST_SCOPE, "(" CD_IPV6_NAME ") IPv6 address includes an unassigned multicast scope value" },
    { DECODE_IPV6_BAD_NEXT_HEADER, "(" CD_IPV6_NAME ") IPv6 header includes an invalid value for the \"next header\" field" },
    { DECODE_IPV6_ROUTE_AND_HOPBYHOP, "(" CD_IPV6_NAME ") IPv6 header includes a routing extension header followed by a hop-by-hop header" },
    { DECODE_IPV6_TWO_ROUTE_HEADERS, "(" CD_IPV6_NAME ") IPv6 header includes two routing extension headers" },
    { DECODE_IPV6_DSTOPTS_WITH_ROUTING, "(" CD_IPV6_NAME ") IPv6 header has destination options followed by a routing header" },
    { DECODE_IPV6_TUNNELED_IPV4_TRUNCATED, "(" CD_IPV6_NAME ") IPV6 tunneled over IPv4, IPv6 header truncated, possible Linux Kernel attack" },
    { DECODE_IPV6_BAD_OPT_LEN, "(" CD_IPV6_NAME ") IPv6 header includes an option which is too big for the containing header" },
    { DECODE_IPV6_UNORDERED_EXTENSIONS, "(" CD_IPV6_NAME ") IPv6 packet includes out-of-order extension headers" },
    { DECODE_IP6_ZERO_HOP_LIMIT, "(" CD_IPV6_NAME ") IPV6 packet has zero hop limit" },
    { DECODE_IPV6_ISATAP_SPOOF, "(" CD_IPV6_NAME ") BAD-TRAFFIC ISATAP-addressed IPv6 traffic spoofing attempt" },
    { DECODE_IPV6_BAD_FRAG_PKT, "(" CD_IPV6_NAME ") bogus fragmentation packet. Possible BSD attack" },
    { DECODE_IPV6_ROUTE_ZERO, "(" CD_IPV6_NAME ") IPV6 routing type 0 extension header" },
    { DECODE_IP6_EXCESS_EXT_HDR, "(decode) too many IP6 extension headers" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

Ipv6Module::Ipv6Module() : DecodeModule(CD_IPV6_NAME, ipv6_params)
{ }

const RuleMap* Ipv6Module::get_rules() const
{ return ipv6_rules; }

