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
#include "codecs/codec_events.h"


namespace
{

// yes, macros are necessary. The API and class constructor require different strings.
#define CD_PIM_NAME "cd_pim"

class PimCodec : public Codec
{
public:
    PimCodec() : Codec(CD_PIM_NAME){};
    ~PimCodec() {};


    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

};

const uint16_t IPPROTO_ID_PIM = 103;

} // namespace


void PimCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ID_PIM);
}

bool PimCodec::decode(const uint8_t* raw_pkt, const uint32_t raw_len, 
        Packet* p, uint16_t& /*lyr_len*/, uint16_t& /*next_prot_id*/)
{
    codec_events::decoder_event(p, DECODE_IP_BAD_PROTO);
    p->data = raw_pkt;
    p->dsize = (uint16_t)raw_len;
    return true;
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{
    return new PimCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const CodecApi pim_api =
{
    {
        PT_CODEC,
        CD_PIM_NAME,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ctor,
    dtor,
};


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &pim_api.base,
    nullptr
};
#else
const BaseApi* cd_pim = &pim_api.base;
#endif
