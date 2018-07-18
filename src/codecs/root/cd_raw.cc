//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
// cd_raw.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sfbpf_dlt.h>

#include "framework/codec.h"

using namespace snort;

#define CD_RAW_NAME "raw"
#define CD_RAW_HELP_STR "support for raw IP"
#define CD_RAW_HELP ADD_DLT(CD_RAW_HELP_STR, DLT_RAW)

namespace
{
class RawCodec : public Codec
{
public:
    RawCodec() : Codec(CD_RAW_NAME) { }

    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void get_data_link_type(std::vector<int>&) override;
};
} // namespace

bool RawCodec::decode(const RawData& raw, CodecData& data, DecodeData&)
{
    uint8_t ipver = (raw.data[0] & 0xf0);

    if (ipver == 0x40)
        data.next_prot_id = ProtocolId::ETHERTYPE_IPV4;
    else if (ipver == 0x60)
        data.next_prot_id = ProtocolId::ETHERTYPE_IPV6;
    else
        return false;

    return true;
}

void RawCodec::get_data_link_type(std::vector<int>& v)
{
    v.push_back(DLT_RAW);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new RawCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi raw_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_RAW_NAME,
        CD_RAW_HELP,
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
const BaseApi* cd_raw[] =
#endif
{
    &raw_api.base,
    nullptr
};
