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
// cd_dstopts.cc author Josh Rosenbaum <jorosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "codecs/codec_events.h"
#include "protocols/protocol_ids.h"
#include "protocols/packet.h"
#include "main/snort.h"
#include "detection/fpdetect.h"
#include "codecs/ipv6_util.h"


namespace
{

#define CD_DSTOPTS_NAME "codec_ipv6_dstopts"

class Ipv6DSTOptsCodec : public Codec
{
public:
    Ipv6DSTOptsCodec() : Codec(CD_DSTOPTS_NAME){};
    ~Ipv6DSTOptsCodec() {};


    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
    virtual bool update(Packet*, Layer*, uint32_t* len);

};

struct IP6Dest
{
    uint8_t ip6dest_nxt;
    uint8_t ip6dest_len;
    /* options follow */
    uint8_t ip6dest_pad[6];
} ;

} // anonymous namespace


bool Ipv6DSTOptsCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    const IP6Dest *dsthdr = reinterpret_cast<const IP6Dest *>(raw_pkt);

    /* See if there are any ip_proto only rules that match */
    fpEvalIpProtoOnlyRules(snort_conf->ip_proto_only_lists, p, IPPROTO_ID_DSTOPTS);
    ipv6_util::CheckIPv6ExtensionOrder(p);


    if(len < sizeof(IP6Dest))
    {
        codec_events::decoder_event(p, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    if ( p->ip6_extension_count >= IP6_EXTMAX )
    {
        codec_events::decoder_event(p, DECODE_IP6_EXCESS_EXT_HDR);
        return false;
    }

    if (dsthdr->ip6dest_nxt == IPPROTO_ROUTING)
    {
        codec_events::decoder_event(p, DECODE_IPV6_DSTOPTS_WITH_ROUTING);
    }

    lyr_len = sizeof(IP6Dest) + (dsthdr->ip6dest_len << 3);
    if(lyr_len > len)
    {
        codec_events::decoder_event(p, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }


    p->ip6_extensions[p->ip6_extension_count].type = IPPROTO_ID_DSTOPTS;
    p->ip6_extensions[p->ip6_extension_count].data = raw_pkt;
    p->ip6_extension_count++;
    next_prot_id = dsthdr->ip6dest_nxt;

    return true;
}


void Ipv6DSTOptsCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ID_DSTOPTS);
}

bool Ipv6DSTOptsCodec::update(Packet* p, Layer* lyr, uint32_t* len)
{
    if ( lyr == (p->layers + p->next_layer - 1) )
        *len += p->dsize;

    *len += lyr->length;
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{
    return new Ipv6DSTOptsCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const CodecApi ipv6_dstopts_api =
{
    {
        PT_CODEC,
        CD_DSTOPTS_NAME,
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
    &ipv6_dstopts_api.base,
    nullptr
};
#else
const BaseApi* cd_dstopts = &ipv6_dstopts_api.base;
#endif
