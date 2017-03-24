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
// cd_swipe.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"

#define CD_SWIPE_NAME "swipe"
#define CD_SWIPE_HELP "support for Swipe"

namespace
{
class SwipeCodec : public Codec
{
public:
    SwipeCodec() : Codec(CD_SWIPE_NAME) { }
    ~SwipeCodec() { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};
} // namespace

void SwipeCodec::get_protocol_ids(std::vector<ProtocolId>& proto_ids)
{ proto_ids.push_back(ProtocolId::SWIPE); }

bool SwipeCodec::decode(const RawData&, CodecData& codec, DecodeData&)
{
    // currently unsupported
    codec_event(codec, DECODE_IP_BAD_PROTO);
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new SwipeCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi swipe_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_SWIPE_NAME,
        CD_SWIPE_HELP,
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
#else
const BaseApi* cd_swipe[] =
#endif
{
    &swipe_api.base,
    nullptr
};

