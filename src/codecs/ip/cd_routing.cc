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
// cd_routing.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"
#include "protocols/protocol_ids.h"
#include "main/snort.h"
#include "detection/fpdetect.h"
#include "protocols/ipv6.h"
#include "codecs/ip/ip_util.h"

#define CD_IPV6_ROUTING_NAME "ipv6_routing"
#define CD_IPV6_ROUTING_HELP "support for IPv6 routing extension"

namespace
{

class Ipv6RoutingCodec : public Codec
{
public:
    Ipv6RoutingCodec() : Codec(CD_IPV6_ROUTING_NAME){};
    ~Ipv6RoutingCodec() {};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);    
};

struct IP6Route
{
    uint8_t ip6rte_nxt;
    uint8_t ip6rte_len;
    uint8_t ip6rte_type;
    uint8_t ip6rte_seg_left;
    /* type specific data follows */
} ;

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
    struct in6_addr ip6rte0_addr[1];  /* Up to 23 IP6 addresses */
} ;
#endif

} // namespace


bool Ipv6RoutingCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    const IP6Route *rte = reinterpret_cast<const IP6Route *>(raw_pkt);

    fpEvalIpProtoOnlyRules(snort_conf->ip_proto_only_lists, p, IPPROTO_ID_ROUTING);



    if(raw_len < ip::MIN_EXT_LEN)
    {
        codec_events::decoder_event(p, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    if ( p->ip6_extension_count >= IP6_EXTMAX)
    {
        codec_events::decoder_event(p, DECODE_IP6_EXCESS_EXT_HDR);
        return false;
    }

    if (raw_len < sizeof(IP6Route))
    {
        codec_events::decoder_event(p, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    /* Routing type 0 extension headers are evil creatures. */
    if (rte->ip6rte_type == 0)
        codec_events::decoder_event(p, DECODE_IPV6_ROUTE_ZERO);

    if (rte->ip6rte_nxt == IPPROTO_ID_HOPOPTS)
        codec_events::decoder_event(p, DECODE_IPV6_ROUTE_AND_HOPBYHOP);

    if (rte->ip6rte_nxt == IPPROTO_ID_ROUTING)
        codec_events::decoder_event(p, DECODE_IPV6_TWO_ROUTE_HEADERS);

    
    lyr_len = ip::MIN_EXT_LEN + (rte->ip6rte_len << 3);
    if(lyr_len > raw_len)
    {
        codec_events::decoder_event(p, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }


    p->ip6_extension_count++;
    next_prot_id = rte->ip6rte_nxt;

    // check header ordering up thru frag header
    ip_util::CheckIPv6ExtensionOrder(p, IPPROTO_ID_ROUTING, next_prot_id);
    p->decode_flags &= DECODE__ROUTING_SEEN;

    return true;
}

void Ipv6RoutingCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ID_ROUTING);
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new Ipv6RoutingCodec(); }

static void dtor(Codec *cd)
{ delete cd; }

static const CodecApi ipv6_routing_api =
{
    {
        PT_CODEC,
        CD_IPV6_ROUTING_NAME,
        CD_IPV6_ROUTING_HELP,
        CDAPI_PLUGIN_V0,
        0,
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
{
    &ipv6_routing_api.base,
    nullptr
};
#else
const BaseApi* cd_routing = &ipv6_routing_api.base;
#endif
