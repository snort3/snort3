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
// ipv6_util.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/ip/ip_util.h"
#include "protocols/packet.h"
#include "codecs/codec_events.h"

namespace ip_util
{


constexpr int IPV6_ORDER_MAX = 7;
static inline int IPV6ExtensionOrder(uint8_t type)
{
    switch (type)
    {
        case IPPROTO_ID_HOPOPTS:   return 1;
        case IPPROTO_ID_DSTOPTS:   return 2;
        case IPPROTO_ID_ROUTING:   return 3;
        case IPPROTO_ID_FRAGMENT:  return 4;
        case IPPROTO_ID_AUTH:      return 5;
        case IPPROTO_ID_ESP:       return 6;
        default:                   return IPV6_ORDER_MAX;
    }
}


bool CheckIPV6HopOptions(const RawData& raw)
{
    const ip::IP6Extension* const exthdr =
        reinterpret_cast<const ip::IP6Extension*>(raw.data);

    const uint8_t* pkt =
        reinterpret_cast<const uint8_t*>(raw.data);

    const uint32_t total_octets = (exthdr->ip6e_len * 8) + 8;
    const uint8_t *hdr_end = pkt + total_octets;
    uint8_t oplen;

    if (raw.len < total_octets)
        codec_events::decoder_event(DECODE_IPV6_TRUNCATED_EXT);

    /* Skip to the options */
    pkt += 2;

    /* Iterate through the options, check for bad ones */
    while (pkt < hdr_end)
    {
        const ip::HopByHopOptions type = static_cast<ip::HopByHopOptions>(*pkt);
        switch (type)
        {
            case ip::HopByHopOptions::PAD1:
                pkt++;
                break;
            case ip::HopByHopOptions::PADN:
            case ip::HopByHopOptions::JUMBO:
            case ip::HopByHopOptions::RTALERT:
            case ip::HopByHopOptions::TUNNEL_ENCAP:
            case ip::HopByHopOptions::QUICK_START:
            case ip::HopByHopOptions::CALIPSO:
            case ip::HopByHopOptions::HOME_ADDRESS:
            case ip::HopByHopOptions::ENDPOINT_IDENT:
                oplen = *(++pkt);
                if ((pkt + oplen + 1) > hdr_end)
                {
                    codec_events::decoder_event(DECODE_IPV6_BAD_OPT_LEN);
                    return false;
                }
                pkt += oplen + 1;
                break;
            default:
                codec_events::decoder_event(DECODE_IPV6_BAD_OPT_TYPE);
                return false;
        }
    }

    return true;
}

/* Check for out-of-order IPv6 Extension Headers */
void CheckIPv6ExtensionOrder(CodecData& codec, const uint8_t proto)
{
    const uint8_t current_order = IPV6ExtensionOrder(proto);
    const uint8_t next_order = IPV6ExtensionOrder(codec.next_prot_id);

    if (current_order <= codec.curr_ip6_extension)
    {
        /* A second "Destination Options" header is allowed iff:
           1) A routing header was already seen, and
           2) The second destination header is the last one before the upper layer.
        */
        if (!((codec.codec_flags & CODEC_ROUTING_SEEN) &&
              (proto == IPPROTO_ID_DSTOPTS) &&
              (next_order == IPV6_ORDER_MAX)))
        {
            codec_events::decoder_event(DECODE_IPV6_UNORDERED_EXTENSIONS);
        }
    }
    else
    {
        codec.curr_ip6_extension = current_order;
    }

    if (proto == IPPROTO_ID_ROUTING)
        codec.codec_flags |= CODEC_ROUTING_SEEN;
}

#if 0
// FIXIT-M Delete after testing.  Currently comment for reference
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
                codec_events::decoder_event(DECODE_IPV6_UNORDERED_EXTENSIONS);
            }
        }

        current_type_order = next_type_order;
    }
}
#endif


} // namespace ipv6_util

