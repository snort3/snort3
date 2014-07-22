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
// cd_ethloopback.cc author Josh Rosenbaum <jrosenba@cisco.com>


#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"

namespace
{

#define CD_ETHLOOPBACK_NAME "ethloopback"


class EthLoopbackCodec : public Codec
{
public:
    EthLoopbackCodec() : Codec(CD_ETHLOOPBACK_NAME){};
    ~EthLoopbackCodec(){};


    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    
};

const uint16_t ETHERNET_TYPE_LOOP = 0x9000;


} // anonymous namespace


void EthLoopbackCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERNET_TYPE_LOOP);
}

bool EthLoopbackCodec::decode(const uint8_t* /*raw_pkt*/, const uint32_t& /*raw_len*/,
        Packet* /*p*/, uint16_t& /*lyr_len*/, uint16_t& /*next_prot_id*/)
{

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "EthLoopback is not supported.\n"););
    return true;
}


//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{
    return new EthLoopbackCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const CodecApi ethloopback_api =
{
    {
        PT_CODEC,
        CD_ETHLOOPBACK_NAME,
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
    &ethloopback_api.base,
    nullptr
};
#else
const BaseApi* cd_ethloopback = &ethloopback_api.base;
#endif


