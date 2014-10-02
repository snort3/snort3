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
// packet.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "protocols/packet.h"
#include "protocols/protocol_ids.h"


uint8_t Packet::ip_proto_next() const
{
    if (ptrs.ip_api.is_ip4())
    {
        return ptrs.ip_api.get_ip4h()->get_proto();
    }
    else if (ptrs.ip_api.is_ip6())
    {
        const ip::IP6Hdr* const ip6h = ptrs.ip_api.get_ip6h();
        int lyr = num_layers-1;

        uint8_t ip_proto = ip6h->get_next();

        for (; lyr >= 0; lyr--)
            if (layers[lyr].start == (uint8_t*)(ip6h))
                break;

#if 0
        if this packet is_ip6, we are gauranteed to find the layer
        if (lyr < 0)
            return IPPROTO_ID_RESERVED;
#endif

        for (; lyr < num_layers; lyr++)
        {
            switch(ip_proto)
            {
                case IPPROTO_ID_HOPOPTS:
                case IPPROTO_ID_DSTOPTS:
                case IPPROTO_ID_ROUTING:
                case IPPROTO_ID_FRAGMENT:
                case IPPROTO_ID_AUTH:
                case IPPROTO_ID_ESP:
                case IPPROTO_ID_MOBILITY:
                {
                    const ip::IP6Extension* const ip6_ext =
                        reinterpret_cast<const ip::IP6Extension*>(layers[lyr].start);
                    ip_proto = ip6_ext->ip6e_nxt;
                    break;
                }
                default:
                {
                    return ip_proto;
                }
            }
        }
    }

    return IPPROTO_ID_RESERVED;
}
