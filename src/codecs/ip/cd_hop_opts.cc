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
// cd_hopopts.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "codecs/codec_events.h"
#include "protocols/ipv6.h"
#include "codecs/ip/ipv6_util.h"
#include "protocols/protocol_ids.h"
#include "main/snort.h"
#include "detection/fpdetect.h"

namespace
{

#define CD_HOPOPTS_NAME "ipv6_hop_opts"

class Ipv6HopOptsCodec : public Codec
{
public:
    Ipv6HopOptsCodec() : Codec(CD_HOPOPTS_NAME) {};
    ~Ipv6HopOptsCodec() {};

    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
    virtual bool update(Packet*, Layer*, uint32_t* len);
};


struct IP6HopByHop
{
    uint8_t ip6hbh_nxt;
    uint8_t ip6hbh_len;
    /* options follow */
    uint8_t ip6hbh_pad[6];
};


} // anonymous namespace


/*
 * Class functions
 */

bool Ipv6HopOptsCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    const IP6HopByHop *hbh_hdr = reinterpret_cast<const IP6HopByHop*>(raw_pkt);


    if (raw_len < sizeof(IP6HopByHop))
    {
        codec_events::decoder_event(p, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    if ( p->ip6_extension_count >= IP6_EXTMAX )
    {
        codec_events::decoder_event(p, DECODE_IP6_EXCESS_EXT_HDR);
        return false;
    }

    /* See if there are any ip_proto only rules that match */
    fpEvalIpProtoOnlyRules(snort_conf->ip_proto_only_lists, p, IPPROTO_ID_HOPOPTS);
    ipv6_util::CheckIPv6ExtensionOrder(p);

    lyr_len = sizeof(IP6HopByHop) + (hbh_hdr->ip6hbh_len << 3);
    next_prot_id = (uint16_t) hbh_hdr->ip6hbh_nxt;

    if(lyr_len > raw_len)
    {
        codec_events::decoder_event(p, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    p->ip6_extensions[p->ip6_extension_count].type = IPPROTO_ID_HOPOPTS;
    p->ip6_extensions[p->ip6_extension_count].data = raw_pkt;
    p->ip6_extension_count++;


    if ( ipv6_util::CheckIPV6HopOptions(raw_pkt, raw_len, p))
        return true;
    return false;
}

void Ipv6HopOptsCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ID_HOPOPTS);
}

bool Ipv6HopOptsCodec::update(Packet* p, Layer* lyr, uint32_t* len)
{
    if ( lyr == (p->layers + p->num_layers - 1) )
        *len += p->dsize;

    *len += lyr->length;
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{
    return new Ipv6HopOptsCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const CodecApi ipv6_hopopts_api =
{
    {
        PT_CODEC,
        CD_HOPOPTS_NAME,
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
    &ipv6_hopopts_api.base,
    nullptr
};
#else
const BaseApi* cd_hopopts = &ipv6_hopopts_api.base;
#endif



