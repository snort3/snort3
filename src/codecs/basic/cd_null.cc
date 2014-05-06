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
// cd_null.cc author Josh Rosenbaum <jorosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "events/codec_events.h"
#include "protocols/protocol_ids.h"

namespace
{

class NullCodec : public Codec
{
public:
    NullCodec() : Codec("null"){};
    ~NullCodec(){};

    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id) { return false; };
    virtual inline bool is_default_codec() { return true; };
};

} // namespace




//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------



void NullCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(FINISHED_DECODE);
    // placeholder to avoid error
}

static Codec* ctor()
{
    return new NullCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const char* name = "null";
static const CodecApi null_api =
{
    {
        PT_CODEC,
        name,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr,
    },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
};

const BaseApi* cd_null = &null_api.base;
