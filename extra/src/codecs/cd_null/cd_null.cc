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
// cd_null.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sfbpf_dlt.h>

#include "framework/codec.h"

#define CD_NULL_NAME "null"
#define CD_NULL_HELP_STR "support for null encapsulation"
#define CD_NULL_HELP ADD_DLT(CD_NULL_HELP_STR, DLT_NULL)

namespace
{
class NullCodec : public Codec
{
public:
    NullCodec() : Codec(CD_NULL_NAME) { }
    ~NullCodec() { }

    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void get_data_link_type(std::vector<int>&) override;
};
} // namespace

static const uint16_t NULL_HDRLEN = 4;

bool NullCodec::decode(const RawData& raw, CodecData& data, DecodeData&)
{
    if (raw.len < NULL_HDRLEN)
        return false;

    data.lyr_len = NULL_HDRLEN;
    data.next_prot_id = ProtocolId::ETHERTYPE_IPV4;
    return true;
}

void NullCodec::get_data_link_type(std::vector<int>& v)
{ v.push_back(DLT_NULL); }

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new NullCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi null_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_NULL_NAME,
        CD_NULL_HELP,
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
    &null_api.base,
    nullptr
};
