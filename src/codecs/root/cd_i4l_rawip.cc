//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// cd_i4l_rawip.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pcap.h>
#include "framework/codec.h"

#define I4L_RAWIP_NAME "i4l_rawip"
#define I4L_RAWIP_HELP_STR "support for I4L IP"

#ifdef DLT_I4L_RAWIP
#define I4L_RAWIP_HELP ADD_DLT(I4L_RAWIP_HELP_STR, DLT_I4L_RAWIP)
#else
#define I4L_RAWIP_HELP I4L_RAWIP_HELP_STR
#endif

namespace
{
class I4LRawIpCodec : public Codec
{
public:
    I4LRawIpCodec() : Codec(I4L_RAWIP_NAME) { }
    ~I4LRawIpCodec() { }

    void get_data_link_type(std::vector<int>&) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};
} // namespace

void I4LRawIpCodec::get_data_link_type(std::vector<int>& v)
{
#ifdef DLT_I4L_RAWIP
    v.push_back(DLT_I4L_RAWIP);
#else
    UNUSED(v);
#endif
}

bool I4LRawIpCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if (raw.len < 2)
        return false;

    codec.lyr_len = 2;
    codec.next_prot_id = ETHERTYPE_IPV4;
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new I4LRawIpCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi i4l_rawip_api =
{
    {
        PT_CODEC,
        I4L_RAWIP_NAME,
        I4L_RAWIP_HELP,
        CDAPI_PLUGIN_V0,
        0,
        nullptr, // mod_ctor
        nullptr  // mod_dtor
    },
    nullptr, // ginit
    nullptr, // gterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,
    dtor,
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &i4l_rawip_api.base,
    nullptr
};
#else
const BaseApi* cd_i4l_rawip = &i4l_rawip_api.base;
#endif

