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
// cd_dstopts.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort.h"
#include "framework/codec.h"
#include "protocols/protocol_ids.h"
#include "protocols/packet.h"
#include "codecs/codec_events.h"
#include "codecs/ip/ip_util.h"

#define CD_DSTOPTS_NAME "ipv6_dst_opts"
#define CD_DSTOPTS_HELP "support for ipv6 destination options"

namespace
{

class Ipv6DSTOptsCodec : public Codec
{
public:
    Ipv6DSTOptsCodec() : Codec(CD_DSTOPTS_NAME){};
    ~Ipv6DSTOptsCodec() {};


    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const RawData&, CodecData&, SnortData&);
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


bool Ipv6DSTOptsCodec::decode(const RawData& raw, CodecData& codec, SnortData&)
{
    const IP6Dest* const dsthdr = reinterpret_cast<const IP6Dest *>(raw.data);

    if(raw.len < sizeof(IP6Dest))
    {
        codec_events::decoder_event(codec, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    if ( codec.ip6_extension_count >= IP6_EXTMAX )
    {
        codec_events::decoder_event(codec, DECODE_IP6_EXCESS_EXT_HDR);
        return false;
    }

    if (dsthdr->ip6dest_nxt == IPPROTO_ROUTING)
        codec_events::decoder_event(codec, DECODE_IPV6_DSTOPTS_WITH_ROUTING);


    codec.lyr_len = sizeof(IP6Dest) + (dsthdr->ip6dest_len << 3);
    if(codec.lyr_len > raw.len)
    {
        codec_events::decoder_event(codec, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    codec.proto_bits |= PROTO_BIT__IP6_EXT;
    codec.ip6_extension_count++;
    codec.next_prot_id = dsthdr->ip6dest_nxt;
    codec.ip6_csum_proto = dsthdr->ip6dest_nxt;


    // must be called AFTER setting next_prot_id
    ip_util::CheckIPv6ExtensionOrder(codec, IPPROTO_ID_DSTOPTS);

    if ( ip_util::CheckIPV6HopOptions(raw, codec))
        return true;
    return false;
}


void Ipv6DSTOptsCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ID_DSTOPTS);
}

bool Ipv6DSTOptsCodec::update(Packet* p, Layer* lyr, uint32_t* len)
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
{ return new Ipv6DSTOptsCodec(); }

static void dtor(Codec *cd)
{ delete cd; }

static const CodecApi ipv6_dstopts_api =
{
    {
        PT_CODEC,
        CD_DSTOPTS_NAME,
        CD_DSTOPTS_HELP,
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
