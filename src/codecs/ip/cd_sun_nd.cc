//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
// cd_sun_nd.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"

namespace
{
// yes, macros are necessary. The API and class constructor require different strings.
#define CD_SUN_ND_NAME "sun_nd"
#define CD_SUN_ND_HELP "support for Sun ND"

class SunNdCodec : public Codec
{
public:
    SunNdCodec() : Codec(CD_SUN_ND_NAME) { }
    ~SunNdCodec() { }

    void get_protocol_ids(std::vector<ProtocolId>&) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};

} // namespace

void SunNdCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.push_back(ProtocolId::SUN_ND);
}

bool SunNdCodec::decode(const RawData&, CodecData& codec, DecodeData&)
{
    codec_event(codec, DECODE_IP_BAD_PROTO);
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new SunNdCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi sun_nd_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_SUN_ND_NAME,
        CD_SUN_ND_HELP,
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
#else
const BaseApi* cd_sun_nd[] =
#endif
{
    &sun_nd_api.base,
    nullptr
};

