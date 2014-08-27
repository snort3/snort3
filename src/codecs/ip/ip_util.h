/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
// ipv6_util.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef IPV6_UTIL_H
#define IPV6_UTIL_H

#include "protocols/ipv6.h"
#include "protocols/protocol_ids.h"
#include "protocols/packet.h"
#include "framework/codec.h"


namespace ip_util
{

bool CheckIPV6HopOptions(const uint8_t *pkt, uint32_t len, Packet *p);
void CheckIPv6ExtensionOrder(Packet *p);

static inline int IPV6ExtensionOrder(uint8_t type)
{
    switch (type)
    {
        case IPPROTO_ID_HOPOPTS:   return 1;
        case IPPROTO_ID_DSTOPTS:   return 2;
        case IPPROTO_ID_ROUTING:   return 3;
        case IPPROTO_ID_FRAGMENT:  return 4;
        case IPPROTO_ID_AH:        return 5;
        case IPPROTO_ID_ESP:       return 6;
        default:                   return 7;
    }
}

static inline icmp::IcmpCode get_icmp4_code(EncodeType et)
{
    switch ( et )
    {
        case EncodeType::ENC_UNR_NET:  return icmp::IcmpCode::NET_UNREACH;
        case EncodeType::ENC_UNR_HOST: return icmp::IcmpCode::HOST_UNREACH;
        case EncodeType::ENC_UNR_PORT: return icmp::IcmpCode::PORT_UNREACH;
        case EncodeType::ENC_UNR_FW:   return icmp::IcmpCode::PKT_FILTERED;
        default: return icmp::IcmpCode::PORT_UNREACH;
    }
}

static inline icmp::Icmp6Code get_icmp6_code(EncodeType et)
{
    switch ( et )
    {
        case EncodeType::ENC_UNR_NET:  return icmp::Icmp6Code::UNREACH_NET;
        case EncodeType::ENC_UNR_HOST: return icmp::Icmp6Code::UNREACH_HOST;
        case EncodeType::ENC_UNR_PORT: return icmp::Icmp6Code::UNREACH_PORT;
        case EncodeType::ENC_UNR_FW:   return icmp::Icmp6Code::UNREACH_FILTER_PROHIB;
        default: return icmp::Icmp6Code::UNREACH_PORT;
    }
}

} // namespace ipv6_util

#endif
