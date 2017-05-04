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
// cd_linux_sll.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sfbpf_dlt.h>

#include "framework/codec.h"
#include "protocols/linux_sll.h"

#define CD_LINUX_SLL_NAME "linux_sll"
#define CD_LINUX_SLL_HELP_STR "support for Linux SLL"
#define CD_LINUX_SLL_HELP ADD_DLT(CD_LINUX_SLL_HELP_STR, DLT_LINUX_SLL)

namespace
{
class LinuxSllCodec : public Codec
{
public:
    LinuxSllCodec() : Codec(CD_LINUX_SLL_NAME) { }
    ~LinuxSllCodec() { }

    void get_data_link_type(std::vector<int>&) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};
} // namespace

void LinuxSllCodec::get_data_link_type(std::vector<int>& v)
{
    v.push_back(DLT_LINUX_SLL);
}

bool LinuxSllCodec::decode(const RawData& raw, CodecData& data, DecodeData&)
{
    /* do a little validation */
    if (raw.len < linux_sll::SLL_HDR_LEN)
        return false;

    /* lay the ethernet structure over the packet data */
    const linux_sll::SLLHdr* const sllh = reinterpret_cast<const linux_sll::SLLHdr*>(raw.data);

    /* grab out the network type */
    data.next_prot_id = static_cast<ProtocolId>(ntohs(sllh->sll_protocol));
    data.lyr_len = linux_sll::SLL_HDR_LEN;
    data.codec_flags |= CODEC_ETHER_NEXT;
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new LinuxSllCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi linux_ssl_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_LINUX_SLL_NAME,
        CD_LINUX_SLL_HELP,
        nullptr,
        nullptr,
    },
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ctor,
    dtor,
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &linux_ssl_api.base,
    nullptr
};
