//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// codec.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codec.h"

#include "codecs/codec_module.h"
#include "detection/detection_engine.h"
#include "events/event_queue.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

EncState::EncState(const ip::IpApi& api, EncodeFlags f, IpProtocol pr,
    uint8_t t, uint16_t data_size) :
    ip_api(api),
    flags(f),
    dsize(data_size),
    next_ethertype(ProtocolId::ETHERTYPE_NOT_SET),
    next_proto(pr),
    ttl(t)
{ }

uint8_t EncState::get_ttl(uint8_t lyr_ttl) const
{
    if ( forward() )
    {
        if (flags & ENC_FLAG_TTL)
            return ttl;
        else
            return lyr_ttl;
    }
    else
    {
        uint8_t new_ttl;

        if (flags & ENC_FLAG_TTL)
            new_ttl = ttl;
        else
            new_ttl = MAX_TTL - lyr_ttl;

        if (new_ttl < MIN_TTL)
            new_ttl = MIN_TTL;

        return new_ttl;
    }
}

/* Logic behind 'buf + size' -- we're encoding the
 * packet from the inside out.  So, whenever we add
 * data, 'allocating' N bytes means moving the pointer
 * N characters farther from the end. For this scheme
 * to work, an empty Buffer means the data pointer is
 * invalid and is actually one byte past the end of the
 * array
 */
Buffer::Buffer(uint8_t* buf, uint32_t size) :
    base(buf + size),
    end(0),
    max_len(size),
    off(0)
{ }

void Codec::codec_event(const CodecData&, CodecSid sid)
{
    DetectionEngine::queue_event(GID_DECODE, sid);
}

bool Codec::CheckIPV6HopOptions(const RawData& raw, CodecData& codec)
{
    const ip::IP6Extension* const exthdr =
        reinterpret_cast<const ip::IP6Extension*>(raw.data);

    const uint8_t* pkt =
        reinterpret_cast<const uint8_t*>(raw.data);

    const uint32_t total_octets = (exthdr->ip6e_len * 8) + 8;
    const uint8_t* hdr_end = pkt + total_octets;
    uint8_t oplen;

    if (raw.len < total_octets)
        codec_event(codec, DECODE_IPV6_TRUNCATED_EXT);

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

        default:
            if ( !(codec.codec_flags & CODEC_IP6_BAD_OPT) )
            {
                codec_event(codec, DECODE_IPV6_BAD_OPT_TYPE);
                codec.codec_flags |= CODEC_IP6_BAD_OPT;
            }
            // fall thru ...

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
                codec_event(codec, DECODE_IPV6_BAD_OPT_LEN);
                return false;
            }
            pkt += oplen + 1;
            break;
        }
    }

    return true;
}

void Codec::CheckIPv6ExtensionOrder(CodecData& codec, const IpProtocol ip_proto)
{
    const uint8_t current_order = ip::IPV6ExtensionOrder(ip_proto);

    if (current_order <= codec.curr_ip6_extension)
    {
        const uint8_t next_order = ip::IPV6IdExtensionOrder(codec.next_prot_id);

        /* A second "Destination Options" header is allowed iff:
           1) A routing header was already seen, and
           2) The second destination header is the last one before the upper layer.
        */
        if ( !((codec.codec_flags & CODEC_ROUTING_SEEN) and
            (ip_proto == IpProtocol::DSTOPTS) and
            (next_order == ip::IPV6_ORDER_MAX)) )
        {
            if ( !(codec.codec_flags & CODEC_IP6_EXT_OOO) )
            {
                codec_event(codec, DECODE_IPV6_UNORDERED_EXTENSIONS);
                codec.codec_flags |= CODEC_IP6_EXT_OOO;
            }
        }
    }
    else
    {
        codec.curr_ip6_extension = current_order;
    }

    if (ip_proto == IpProtocol::ROUTING)
        codec.codec_flags |= CODEC_ROUTING_SEEN;
}

#ifdef UNIT_TEST
TEST_CASE("init", "[buffer]")
{
    uint8_t raw_buf[2];
    Buffer buf(&raw_buf[0], 1);
    CHECK( buf.data() == &raw_buf[1] ); // 1 past the "known" buffer
    CHECK( buf.size() == 0 );
}

TEST_CASE("alloc", "[buffer]")
{
    uint8_t raw_buf[1];
    Buffer buf(raw_buf, 1);
    buf.allocate(1);

    CHECK( buf.data() == &raw_buf[0] );
    CHECK( buf.size() == 1 );
}

TEST_CASE("multi alloc", "[buffer]")
{
    uint8_t raw_buf2[3];
    Buffer buf2(raw_buf2, 3);
    buf2.allocate(1);

    CHECK( buf2.data() == &raw_buf2[2] );
    CHECK( buf2.size() == 1 );

    buf2.allocate(2);
    CHECK( buf2.data() == &raw_buf2[0] );
    CHECK( buf2.size() == 3 );
}

TEST_CASE("clear", "[buffer]")
{
    uint8_t raw_buf[2];
    Buffer buf(raw_buf, 1);
    buf.allocate(1);
    buf.clear();
    
    CHECK( buf.data() == &raw_buf[1] ); // 1 past the "known" buffer
    CHECK( buf.size() == 0 );
}
#endif
