//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// cd_hopopts.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"

using namespace snort;

#define CD_HOPOPTS_NAME "ipv6_hop_opts"
#define CD_HOPOPTS_HELP "support for IPv6 hop options"

namespace
{
class Ipv6HopOptsCodec : public Codec
{
public:
    Ipv6HopOptsCodec() : Codec(CD_HOPOPTS_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};

struct IP6HopByHop
{
    IpProtocol ip6hbh_nxt;
    uint8_t ip6hbh_len;
    /* options follow */
    uint8_t ip6hbh_pad[6];
};
} // anonymous namespace

/*
 * Class functions
 */

bool Ipv6HopOptsCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    const IP6HopByHop* hbh_hdr = reinterpret_cast<const IP6HopByHop*>(raw.data);

    if (raw.len < sizeof(IP6HopByHop))
    {
        codec_event(codec, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    if ( SnortConfig::get_conf()->hit_ip6_maxopts(codec.ip6_extension_count) )
    {
        codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR);
        return false;
    }

    codec.lyr_len = sizeof(IP6HopByHop) + (hbh_hdr->ip6hbh_len << 3);
    if (codec.lyr_len > raw.len)
    {
        codec_event(codec, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    codec.next_prot_id = (ProtocolId)hbh_hdr->ip6hbh_nxt;
    codec.ip6_csum_proto = hbh_hdr->ip6hbh_nxt;
    codec.ip6_extension_count++;
    codec.proto_bits |= PROTO_BIT__IP6_EXT;

    // must be called AFTER setting next_prot_id
    CheckIPv6ExtensionOrder(codec, IpProtocol::HOPOPTS);
    if ( CheckIPV6HopOptions(raw, codec))
        return true;

    return false;
}

void Ipv6HopOptsCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.push_back(ProtocolId::HOPOPTS);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new Ipv6HopOptsCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi ipv6_hopopts_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_HOPOPTS_NAME,
        CD_HOPOPTS_HELP,
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

/*  This codec is static to ensure the symbols CheckIPV6HopOptions
 *  and CheckIPv6ExtensionOrder are included in the binary.
 */

//#ifdef BUILDING_SO
//SO_PUBLIC const BaseApi* snort_plugins[] =
//#else
const BaseApi* cd_hopopts[] =
//#endif
{
    &ipv6_hopopts_api.base,
    nullptr
};

