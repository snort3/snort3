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

// cd_icmp6_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/ip/cd_icmp6_module.h"

// rules which will loaded into snort. 
// You can now reference these rules by calling a codec_event
// in your main codec's functions
static const RuleMap icmp6_rules[] =
{
    { DECODE_ICMP6_HDR_TRUNC, "(" CD_ICMP6_NAME ") truncated ICMP6 header" },
    { DECODE_ICMP6_TYPE_OTHER, "(" CD_ICMP6_NAME ") ICMP6 type not decoded" },
    { DECODE_ICMP6_DST_MULTICAST, "(" CD_ICMP6_NAME ") ICMP6 packet to multicast address" },
    { DECODE_ICMPV6_TOO_BIG_BAD_MTU, "(" CD_ICMP6_NAME ") ICMPv6 packet of type 2 (message too big) with MTU field < 1280" },
    { DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE, "(" CD_ICMP6_NAME ") ICMPv6 packet of type 1 (destination unreachable) with non-RFC 2463 code" },
    { DECODE_ICMPV6_SOLICITATION_BAD_CODE, "(" CD_ICMP6_NAME ") ICMPv6 router solicitation packet with a code not equal to 0" },
    { DECODE_ICMPV6_ADVERT_BAD_CODE, "(" CD_ICMP6_NAME ") ICMPv6 router advertisement packet with a code not equal to 0" },
    { DECODE_ICMPV6_SOLICITATION_BAD_RESERVED, "(" CD_ICMP6_NAME ") ICMPv6 router solicitation packet with the reserved field not equal to 0" },
    { DECODE_ICMPV6_ADVERT_BAD_REACHABLE, "(" CD_ICMP6_NAME ") ICMPv6 router advertisement packet with the reachable time field set > 1 hour" },
    { DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE, "(" CD_ICMP6_NAME ") ICMPv6 packet of type 1 (destination unreachable) with non-RFC 4443 code" },
    { DECODE_ICMPV6_NODE_INFO_BAD_CODE, "(" CD_ICMP6_NAME ") ICMPv6 node info query/response packet with a code greater than 2" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// rpc module
//-------------------------------------------------------------------------

Icmp6Module::Icmp6Module() : DecodeModule(CD_ICMP6_NAME)
{ }

const RuleMap* Icmp6Module::get_rules() const
{ return icmp6_rules; }

