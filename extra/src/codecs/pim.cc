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

// cd_pim.cc author Josh Rosenbaum <jrosenba@cisco.com>


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "codecs/codec_events.h"


namespace
{

// yes, macros are necessary. The API and class constructor require different strings.
#define CD_PIM_NAME "pim"
#define CD_PIM_HELP "support for protocol independent multicast"

class PimCodec : public Codec
{
public:
    PimCodec() : Codec(CD_PIM_NAME){};
    ~PimCodec() {};


    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual bool decode(const RawData&, CodecData&, SnortData&);

};

const uint16_t IPPROTO_ID_PIM = 103;

} // namespace


void PimCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ID_PIM);
}

bool PimCodec::decode(const RawData&, CodecData& codec, SnortData&)
{
    codec_events::decoder_event(codec, DECODE_IP_BAD_PROTO);
    return true;
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new PimCodec(); }

static void dtor(Codec *cd)
{ delete cd; }


static const CodecApi pim_api =
{
    {
        PT_CODEC,
        CD_PIM_NAME,
        CD_PIM_HELP,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,
    dtor,
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &pim_api.base,
    nullptr
};
