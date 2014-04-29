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
// cd_ah.cc author Josh Rosenbaum <jorosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "framework/codec.h"
#include "events/codec_events.h"

namespace
{

class AhCodec : public Codec
{
public:
    AhCodec() : Codec("ah"){};
    ~AhCodec(){};


    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);


    // DELETE from here and below
    #include "codecs/sf_protocols.h"
    virtual inline PROTO_ID get_proto_id() { return PROTO_AH; };
    
};

static const uint16_t AH_PROT_ID = 51; // RFC 4302


} // anonymous namespace

void AhCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(AH_PROT_ID);
}


bool AhCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{

    IP6Extension *ah = (IP6Extension *)raw_pkt;
    lyr_len = sizeof(*ah) + (ah->ip6e_len << 2);

    if (lyr_len > len)
    {
        return false;
    }

    next_prot_id = ah->ip6e_nxt;
    return true;
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor()
{
    return new AhCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const char* name = "ah";
static const CodecApi ah_api =
{
    {
        PT_CODEC,
        name, 
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
    &ah_api.base,
    nullptr
};
#else
const BaseApi* cd_ah = &ah_api.base;
#endif



