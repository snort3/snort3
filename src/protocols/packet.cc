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


#if 0
uint8_t Packet::ip_proto_next() const
{
    if (is_ip4())
    {
        return ptrs.ip_api.get_ip4h()->proto();
    }
    else if (is_ip6())
    {
        const ip::IP6Hdr* const ip6h = ptrs.ip_api.get_ip6h();
        int lyr = num_layers-1;


        for (; lyr >= 0; lyr--)
            if (layers[lyr].start == (const uint8_t*)(ip6h))
                break;

#if 0
        Since this packet 'is_ip6()', we ar gauranteed to find the layer
        if (lyr < 0)
            return IPPROTO_ID_RESERVED;
#endif

        while (lyr < num_layers)
        {
            const uint16_t prot = layers[lyr].prot_id;

            if (!is_ip_protocol(prot))
                return (uint8_t)prot;

            ++lyr;
        }
    }

    return IPPROTO_ID_RESERVED;
}
#endif

bool Packet::get_ip_proto_next(uint8_t &lyr, uint8_t& proto) const
{
    if (lyr > num_layers)
        return false;

    while (lyr < num_layers)
    {
        switch(layers[lyr].prot_id)
        {
        case IPPROTO_ID_IPIP:
        case IPPROTO_ID_IPV6:
        case ETHERTYPE_IPV4:
        case ETHERTYPE_IPV6:
            // move past this IP layer and any IPv6 extensions.
            while (++lyr < num_layers && is_ip6_extension(layers[lyr].prot_id));

            if (lyr >= num_layers)
            {
                return false;
            }
            else
            {
                proto = layers[lyr].prot_id;
                return true;
            }

        default:
            ++lyr;
        }

    }

    return false;
}
