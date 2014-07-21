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
// cd_swipe.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "codecs/codec_events.h"

namespace{

#define CD_SWIPE_NAME "cd_swipe"


class SwipeCodec : public Codec
{
public:
    SwipeCodec() : Codec(CD_SWIPE_NAME){};
    virtual ~SwipeCodec(){};
    
    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t* raw_packet, const uint32_t& raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t &);
};
} // namespace

static const uint16_t SWIPE_PROT_ID = 53;

void SwipeCodec::get_protocol_ids(std::vector<uint16_t> &proto_ids)
{
    proto_ids.push_back(SWIPE_PROT_ID);
}


bool SwipeCodec::decode(const uint8_t* /*raw_packet*/, const uint32_t& /*raw_len*/,
        Packet *p, uint16_t& /*lyr_len*/, uint16_t& /*next_prot_id*/)
{
    // currently unsupported
    codec_events::decoder_event(p, DECODE_IP_BAD_PROTO);
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec *ctor(Module*)
{
    return new SwipeCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const CodecApi swipe_api =
{
    {
        PT_CODEC,
        CD_SWIPE_NAME,
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
    &swipe_api.base,
    nullptr
};
#else
const BaseApi* cd_swipe = &swipe_api.base;
#endif



