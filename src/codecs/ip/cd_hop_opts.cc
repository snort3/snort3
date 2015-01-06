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
// cd_hopopts.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "codecs/codec_events.h"
#include "protocols/ipv6.h"
#include "codecs/ip/ip_util.h"
#include "protocols/protocol_ids.h"
#include "main/snort.h"
#include "detection/fpdetect.h"

#define CD_HOPOPTS_NAME "ipv6_hop_opts"
#define CD_HOPOPTS_HELP "support for IPv6 hop options"

namespace
{

class Ipv6HopOptsCodec : public Codec
{
public:
    Ipv6HopOptsCodec() : Codec(CD_HOPOPTS_NAME) {};
    ~Ipv6HopOptsCodec() {};

    void get_protocol_ids(std::vector<uint16_t>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};


struct IP6HopByHop
{
    uint8_t ip6hbh_nxt;
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
    const IP6HopByHop *hbh_hdr = reinterpret_cast<const IP6HopByHop*>(raw.data);


    if (raw.len < sizeof(IP6HopByHop))
    {
        codec_events::decoder_event(codec, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    if ( snort_conf->hit_ip6_maxopts(codec.ip6_extension_count) )
    {
        codec_events::decoder_event(codec, DECODE_IP6_EXCESS_EXT_HDR);
        return false;
    }


    codec.lyr_len = sizeof(IP6HopByHop) + (hbh_hdr->ip6hbh_len << 3);
    if(codec.lyr_len > raw.len)
    {
        codec_events::decoder_event(codec, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    codec.next_prot_id = (uint16_t) hbh_hdr->ip6hbh_nxt;
    codec.ip6_csum_proto = hbh_hdr->ip6hbh_nxt;
    codec.ip6_extension_count++;
    codec.proto_bits |= PROTO_BIT__IP6_EXT;

    // must be called AFTER setting next_prot_id
    ip_util::CheckIPv6ExtensionOrder(codec, IPPROTO_ID_HOPOPTS);
    if ( ip_util::CheckIPV6HopOptions(raw, codec))
        return true;

    return false;
}

void Ipv6HopOptsCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ID_HOPOPTS);
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new Ipv6HopOptsCodec(); }

static void dtor(Codec *cd)
{ delete cd; }

static const CodecApi ipv6_hopopts_api =
{
    {
        PT_CODEC,
        CD_HOPOPTS_NAME,
        CD_HOPOPTS_HELP,
        CDAPI_PLUGIN_V0,
        0,
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
{
    &ipv6_hopopts_api.base,
    nullptr
};
#else
const BaseApi* cd_hopopts = &ipv6_hopopts_api.base;
#endif



