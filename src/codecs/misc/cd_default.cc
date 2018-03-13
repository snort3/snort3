//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// cd_default.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"

using namespace snort;

#define CD_DEFAULT_NAME "unknown"
#define CD_DEFAULT_HELP "support for unknown protocols"

namespace
{
class DefaultCodec : public Codec
{
public:
    DefaultCodec() : Codec(CD_DEFAULT_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override
    { v.push_back(ProtocolId::FINISHED_DECODE); }

    bool decode(const RawData&, CodecData&, DecodeData&) override
    { return false; }
};
} // namespace

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new DefaultCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi default_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_DEFAULT_NAME,
        CD_DEFAULT_HELP,
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

const CodecApi* default_codec[] =
{
    &default_api,
    nullptr
};

