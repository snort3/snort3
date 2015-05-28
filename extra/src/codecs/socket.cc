//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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
// cd_socket.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "../daqs/daq_socket.h"
#include "protocols/packet.h"
#include "sfip/sf_ip.h"

#define CD_NAME "socket"
#define CD_HELP_STR "support for sockets / proxied sessions"
#define CD_HELP ADD_DLT(CD_HELP_STR, DLT_SOCKET)

class SocketCodec : public Codec
{
public:
    SocketCodec() : Codec(CD_NAME) { };
    ~SocketCodec() { };

    void get_data_link_type(std::vector<int>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};

void SocketCodec::get_data_link_type(std::vector<int>& v)
{
    v.push_back(DLT_SOCKET);
}

static void set_ip(const DAQ_SktHdr_t* pci, CodecData& codec, DecodeData& snort)
{
    // FIXIT support ip6
    sfip_t sip, dip;
    sfip_set_raw(&sip, &pci->src_addr, AF_INET);
    sfip_set_raw(&dip, &pci->dst_addr, AF_INET);
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
    sfip_t sip, dip;
    sfip_pton("192.168.1.1", &sip);
    sfip_pton("192.168.2.2", &dip);
    snort.ip_api.set(sip, dip);

    snort.sp = 12345;
    snort.dp = 54321;

    codec.proto_bits |= PROTO_BIT__TCP;
}

static void set_flags(
    const DAQ_SktHdr_t* pci, const RawData& raw, CodecData& codec, DecodeData& snort)
{
    if ( pci->flags & DAQ_SKT_FLAG_TO_SERVER )
        snort.decode_flags |= DECODE_C2S;

    if ( pci->flags & DAQ_SKT_FLAG_START_FLOW )
        snort.decode_flags |= DECODE_SOF;

    if ( pci->flags & DAQ_SKT_FLAG_END_FLOW )
    {
        snort.decode_flags |= DECODE_EOF;
        codec.lyr_len = raw.len;
    }
    else
        codec.lyr_len = 0;
}

bool SocketCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    const DAQ_SktHdr_t* pci = (DAQ_SktHdr_t*)raw.pkth->priv_ptr;

    if ( pci->ip_proto )
    {
        set_ip(pci, codec, snort);
        snort.set_pkt_type(PktType::USER);
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
{ return new SocketCodec; }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi socket_api =
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

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &socket_api.base,
    nullptr
};

