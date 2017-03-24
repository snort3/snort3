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
// cd_mobility.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"

// yes, macros are necessary. The API and class constructor require different strings.
#define CD_MOBILE_NAME "ipv6_mobility"
#define CD_MOBILE_HELP "support for mobility"

namespace
{
class MobilityCodec : public Codec
{
public:
    MobilityCodec() : Codec(CD_MOBILE_NAME) { }
    ~MobilityCodec() { }

    void get_protocol_ids(std::vector<ProtocolId>&) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};
} // namespace

void MobilityCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.push_back(ProtocolId::MOBILITY);
}

bool MobilityCodec::decode(const RawData&, CodecData& codec, DecodeData&)
{
    if ( snort_conf->hit_ip6_maxopts(codec.ip6_extension_count) )
    {
        codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR);
        return false;
    }

    codec_event(codec, DECODE_IP_BAD_PROTO);
    codec.proto_bits |= PROTO_BIT__IP6_EXT; // check for any IP related rules
    codec.ip6_extension_count++;
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new MobilityCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi mobility_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_MOBILE_NAME,
        CD_MOBILE_HELP,
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
const BaseApi* cd_mobility[] =
#endif
{
    &mobility_api.base,
    nullptr
};

