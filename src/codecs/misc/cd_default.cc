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
// cd_default.cc author Josh Rosenbaum <jrosenba@cisco.com>


#include "framework/codec.h"
#include "protocols/protocol_ids.h"

#define CD_DEFAULT_NAME "unknown"
#define CD_DEFAULT_HELP "support for unkown protocols"

namespace
{

class DefaultCodec : public Codec
{
public:
    DefaultCodec() : Codec(CD_DEFAULT_NAME){};
    ~DefaultCodec(){};

    virtual void get_protocol_ids(std::vector<uint16_t>& v)
    { v.push_back(FINISHED_DECODE); }

    virtual bool decode(const RawData&, CodecData&, DecodeData&)
    { return false; };
};

} // namespace


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static Codec* ctor(Module*)
{ return new DefaultCodec(); }

static void dtor(Codec *cd)
{ delete cd; }


static const CodecApi default_api =
{
    {
        PT_CODEC,
        CD_DEFAULT_NAME,
        CD_DEFAULT_HELP,
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
