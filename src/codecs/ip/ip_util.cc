/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

bool CheckIPV6HopOptions(const RawData& raw, const CodecData& codec)
{
    const ip::IP6Extension* const exthdr =
        reinterpret_cast<const ip::IP6Extension*>(raw.data);

    const uint8_t* pkt =
        reinterpret_cast<const uint8_t*>(raw.data);

    const uint32_t total_octets = (exthdr->ip6e_len * 8) + 8;
    const uint8_t *hdr_end = pkt + total_octets;
    uint8_t oplen;

    if (raw.len < total_octets)
        codec_events::decoder_event(codec, DECODE_IPV6_TRUNCATED_EXT);

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
                    codec_events::decoder_event(codec, DECODE_IPV6_BAD_OPT_LEN);
                    return false;
                }
                pkt += oplen + 1;
                break;
            default:
                codec_events::decoder_event(codec, DECODE_IPV6_BAD_OPT_TYPE);
                return false;
        }
    }

    return true;
}

/* Check for out-of-order IPv6 Extension Headers */
void CheckIPv6ExtensionOrder(CodecData& codec, const uint8_t proto)
{
    const uint8_t current_order = ip::IPV6ExtensionOrder(proto);

    if (current_order <= codec.curr_ip6_extension)
    {
        const uint8_t next_order = ip::IPV6ExtensionOrder(codec.next_prot_id);

        /* A second "Destination Options" header is allowed iff:
           1) A routing header was already seen, and
           2) The second destination header is the last one before the upper layer.
        */
        if (!((codec.codec_flags & CODEC_ROUTING_SEEN) &&
              (proto == IPPROTO_ID_DSTOPTS) &&
              (next_order == ip::IPV6_ORDER_MAX)))
        {
            codec_events::decoder_event(codec, DECODE_IPV6_UNORDERED_EXTENSIONS);
        }
    }
    else
    {
        codec.curr_ip6_extension = current_order;
    }

    if (proto == IPPROTO_ID_ROUTING)
        codec.codec_flags |= CODEC_ROUTING_SEEN;
}

} // namespace ipv6_util

