//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// cd_user.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <daq_common.h>

#include "daqs/daq_user.h"
#include "framework/codec.h"
#include "packet_io/sfdaq.h"

using namespace snort;

#define CD_NAME "user"
#define CD_HELP_STR "support for user sessions"
#define CD_HELP ADD_DLT(CD_HELP_STR, DLT_USER)

class UserCodec : public Codec
{
public:
    UserCodec() : Codec(CD_NAME) { }

    void get_data_link_type(std::vector<int>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};

void UserCodec::get_data_link_type(std::vector<int>& v)
{
    v.push_back(DLT_USER);
}

static void set_ip(const DAQ_UsrHdr_t* pci, CodecData& codec, DecodeData& snort)
{
    // FIXIT-M support ip6
    SfIp sip, dip;
    sip.set(&pci->src_addr, AF_INET);
    dip.set(&pci->dst_addr, AF_INET);
    snort.ip_api.set(sip, dip);

    snort.sp = pci->src_port;
    snort.dp = pci->dst_port;

    if ( pci->ip_proto == IPPROTO_TCP )
        codec.proto_bits |= PROTO_BIT__TCP;
    else
        codec.proto_bits |= PROTO_BIT__UDP;
}

static void set_key(CodecData& codec, DecodeData& snort)
{
    // FIXIT-L make configurable
    SfIp sip, dip;
    sip.set("192.168.1.1");
    dip.set("192.168.2.2");
    snort.ip_api.set(sip, dip);

    snort.sp = 12345;
    snort.dp = 54321;

    codec.proto_bits |= PROTO_BIT__TCP;
}

static void set_flags(
    const DAQ_UsrHdr_t* pci, const RawData& raw, CodecData& codec, DecodeData& snort)
{
    if ( pci->flags & DAQ_USR_FLAG_TO_SERVER )
        snort.decode_flags |= DECODE_C2S;

    if ( pci->flags & DAQ_USR_FLAG_START_FLOW )
        snort.decode_flags |= DECODE_SOF;

    if ( pci->flags & DAQ_USR_FLAG_END_FLOW )
    {
        snort.decode_flags |= DECODE_EOF;
        codec.lyr_len = raw.len;
    }
    else
        codec.lyr_len = 0;
}

bool UserCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    DAQ_QueryFlow_t query { DAQ_USR_QUERY_PCI, 0, nullptr };

    if ( SFDAQ::get_local_instance()->query_flow(raw.pkth, &query) != DAQ_SUCCESS or
        query.length != sizeof(DAQ_UsrHdr_t) )
    {
        return false;
    }

    const DAQ_UsrHdr_t* pci = (DAQ_UsrHdr_t*)query.value;

    if ( !pci )
        return false;

    if ( pci->ip_proto )
    {
        set_ip(pci, codec, snort);
        snort.set_pkt_type(PktType::PDU);
    }
    else
    {
        set_key(codec, snort);
        snort.set_pkt_type(PktType::FILE);
    }

    set_flags(pci, raw, codec, snort);
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new UserCodec; }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi user_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_NAME,
        CD_HELP,
        nullptr,  // mod_ctor
        nullptr,  // mod_dtor
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,
    dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* cd_user[] =
#endif
{
    &user_api.base,
    nullptr
};

