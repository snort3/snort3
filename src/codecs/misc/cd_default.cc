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
#include "codecs/codec_events.h"
#include "protocols/protocol_ids.h"

namespace
{

#define CD_DEFAULT_NAME "codec_default"

class DefaultCodec : public Codec
{
public:
    DefaultCodec() : Codec(CD_DEFAULT_NAME){};
    ~DefaultCodec(){};

    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t*, const uint32_t, 
        Packet*, uint16_t&, uint16_t&) { return false; };
};

} // namespace


void DefaultCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(FINISHED_DECODE);
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static Codec* ctor(Module*)
{
    return new DefaultCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const CodecApi default_api =
{
    {
        PT_CODEC,
        CD_DEFAULT_NAME,
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

const CodecApi* default_codec = &default_api;
