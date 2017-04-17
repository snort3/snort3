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
// cd_raw4.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sfbpf_dlt.h>

#include "framework/codec.h"

#define CD_RAW4_NAME "raw4"
#define CD_RAW4_HELP_STR "support for unencapsulated IPv4"
#define CD_RAW4_HELP ADD_DLT(ADD_DLT(CD_RAW4_HELP_STR, DLT_RAW), DLT_IPV4)

namespace
{
class Raw4Codec : public Codec
{
public:
    Raw4Codec() : Codec(CD_RAW4_NAME) { }
    ~Raw4Codec() { }

    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void get_data_link_type(std::vector<int>&) override;
};
} // namespace

bool Raw4Codec::decode(const RawData&, CodecData& data, DecodeData&)
{
    data.next_prot_id = ProtocolId::ETHERTYPE_IPV4;
    return true;
}

void Raw4Codec::get_data_link_type(std::vector<int>& v)
{
    v.push_back(DLT_RAW);
    v.push_back(DLT_IPV4);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new Raw4Codec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi raw4_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_RAW4_NAME,
        CD_RAW4_HELP,
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

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &raw4_api.base,
    nullptr
};
