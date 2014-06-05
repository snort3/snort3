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



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"
#include "protocols/ipv6.h"
#include "codecs/ipv6_util.h"
#include "protocols/protocol_ids.h"
#include "main/snort.h"
#include "detection/fpdetect.h"


namespace
{

#define CD_NO_NEXT_NAME "codec_ipv6_no_next"

class Ipv6NoNextCodec : public Codec
{
public:
    Ipv6NoNextCodec() : Codec(CD_NO_NEXT_NAME){};
    ~Ipv6NoNextCodec() {};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
    virtual void get_protocol_ids(std::vector<uint16_t>&);    
};


} // namespace


bool Ipv6NoNextCodec::decode(const uint8_t* /*raw_pkt*/, const uint32_t /*len*/, 
        Packet *p, uint16_t& lyr_len, uint16_t& /*next_prot_id*/)
{
    /* See if there are any ip_proto only rules that match */
    fpEvalIpProtoOnlyRules(snort_conf->ip_proto_only_lists, p, IPPROTO_ID_NONEXT);
    ipv6_util::CheckIPv6ExtensionOrder(p);

    p->dsize = 0;
    lyr_len = ipv6::min_ext_len();
    return true;
}


void Ipv6NoNextCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ID_NONEXT);
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{
    return new Ipv6NoNextCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const CodecApi no_next_api =
{
    {
        PT_CODEC,
        CD_NO_NEXT_NAME,
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
    &no_next_api.base,
    nullptr
};
#else
const BaseApi* cd_no_next = &no_next_api.base;
#endif
