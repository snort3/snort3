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
// ipv6_util.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include "codecs/ipv6_util.h"
#include "protocols/packet.h"
#include "codecs/codec_events.h"

namespace ipv6_util
{


#if 0
bool CheckIPV6HopOptions(const uint8_t *pkt, uint32_t len, Packet *p)
{
    IP6Extension *exthdr = (IP6Extension *)pkt;
    uint32_t total_octets = (exthdr->ip6e_len * 8) + 8;
    const uint8_t *hdr_end = pkt + total_octets;
    uint8_t oplen;

    if (len < total_octets)
        codec_events::decoder_event(p, DECODE_IPV6_TRUNCATED_EXT);

    /* Skip to the options */
    pkt += 2;

    /* Iterate through the options, check for bad ones */
    while (pkt < hdr_end)
    {
        const ipv6::HopByHopOptions type = static_cast<ipv6::HopByHopOptions>(*pkt);
        switch (type)
        {
            case ipv6::HopByHopOptions::PAD1:
                pkt++;
                break;
            case ipv6::HopByHopOptions::PADN:
            case ipv6::HopByHopOptions::JUMBO:
            case ipv6::HopByHopOptions::RTALERT:
            case ipv6::HopByHopOptions::TUNNEL_ENCAP:
            case ipv6::HopByHopOptions::QUICK_START:
            case ipv6::HopByHopOptions::CALIPSO:
            case ipv6::HopByHopOptions::HOME_ADDRESS:
            case ipv6::HopByHopOptions::ENDPOINT_IDENT:
                oplen = *(++pkt);
                if ((pkt + oplen + 1) > hdr_end)
                {
                    codec_events::decoder_event(p, DECODE_IPV6_BAD_OPT_LEN);
                    return false;
                }
                pkt += oplen + 1;
                break;
            default:
                codec_events::decoder_event(p, DECODE_IPV6_BAD_OPT_TYPE);
                return false;
        }
    }

    return true;
}

#endif

/* Check for out-of-order IPv6 Extension Headers */
void CheckIPv6ExtensionOrder(Packet *p)
{
    int routing_seen = 0;
    int current_type_order, next_type_order, i;

    if (p->ip6_extension_count > 0)
        current_type_order = IPV6ExtensionOrder(p->ip6_extensions[0].type);

    for (i = 1; i < (p->ip6_extension_count); i++)
    {
        next_type_order = IPV6ExtensionOrder(p->ip6_extensions[i].type);

        if (p->ip6_extensions[i].type == IPPROTO_ROUTING)
            routing_seen = 1;

        if (next_type_order <= current_type_order)
        {
            /* A second "Destination Options" header is allowed iff:
               1) A routing header was already seen, and
               2) The second destination header is the last one before the upper layer.
            */
            if (!routing_seen ||
                !(p->ip6_extensions[i].type == IPPROTO_DSTOPTS) ||
                !(i+1 == p->ip6_extension_count))
            {
                codec_events::decoder_event(p, DECODE_IPV6_UNORDERED_EXTENSIONS);
            }
        }

        current_type_order = next_type_order;
    }
}


} // namespace ipv6_util

