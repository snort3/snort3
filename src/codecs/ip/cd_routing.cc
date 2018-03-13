//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
// cd_routing.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"

using namespace snort;

#define CD_IPV6_ROUTING_NAME "ipv6_routing"
#define CD_IPV6_ROUTING_HELP "support for IPv6 routing extension"

namespace
{
class Ipv6RoutingCodec : public Codec
{
public:
    Ipv6RoutingCodec() : Codec(CD_IPV6_ROUTING_NAME) { }

    bool decode(const RawData&, CodecData&, DecodeData&) override;

    void get_protocol_ids(std::vector<ProtocolId>&) override;
};

struct IP6Route
{
    IpProtocol ip6rte_nxt;
    uint8_t ip6rte_len;
    uint8_t ip6rte_type;
    uint8_t ip6rte_seg_left;
    /* type specific data follows */
};

#if 0
// Keeping this around for future development
struct IP6Route0
{
    uint8_t ip6rte0_nxt;
    uint8_t ip6rte0_len;
    uint8_t ip6rte0_type;
    uint8_t ip6rte0_seg_left;
    uint8_t ip6rte0_reserved;
    uint8_t ip6rte0_bitmap[3];
    struct snort_in6_addr ip6rte0_addr[1];  /* Up to 23 IP6 addresses */
};
#endif
} // namespace

void Ipv6RoutingCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.push_back(ProtocolId::ROUTING); }

bool Ipv6RoutingCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    const IP6Route* const rte = reinterpret_cast<const IP6Route*>(raw.data);

    if (raw.len < ip::MIN_EXT_LEN)
    {
        codec_event(codec, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    if ( SnortConfig::get_conf()->hit_ip6_maxopts(codec.ip6_extension_count) )
    {
        codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR);
        return false;
    }

    if (raw.len < sizeof(IP6Route))
    {
        codec_event(codec, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    /* Routing type 0 extension headers are evil creatures. */
    if (rte->ip6rte_type == 0)
        codec_event(codec, DECODE_IPV6_ROUTE_ZERO);

    if (rte->ip6rte_nxt == IpProtocol::HOPOPTS)
        codec_event(codec, DECODE_IPV6_ROUTE_AND_HOPBYHOP);

    if (rte->ip6rte_nxt == IpProtocol::ROUTING)
        codec_event(codec, DECODE_IPV6_TWO_ROUTE_HEADERS);

    codec.lyr_len = ip::MIN_EXT_LEN + (rte->ip6rte_len << 3);
    if (codec.lyr_len > raw.len)
    {
        codec_event(codec, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    codec.proto_bits |= PROTO_BIT__IP6_EXT; // check ip proto rules against this layer
    codec.ip6_extension_count++;
    codec.next_prot_id = (ProtocolId)rte->ip6rte_nxt;
    codec.ip6_csum_proto = rte->ip6rte_nxt;

    // must be called AFTER setting next_prot_id
    CheckIPv6ExtensionOrder(codec, IpProtocol::ROUTING);
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new Ipv6RoutingCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi ipv6_routing_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_IPV6_ROUTING_NAME,
        CD_IPV6_ROUTING_HELP,
        nullptr,
        nullptr,
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    dtor, // dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* cd_routing[] =
#endif
{
    &ipv6_routing_api.base,
    nullptr
};

