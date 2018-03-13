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
// cd_dst_opts.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"

using namespace snort;

#define CD_DSTOPTS_NAME "ipv6_dst_opts"
#define CD_DSTOPTS_HELP "support for ipv6 destination options"

namespace
{
class Ipv6DSTOptsCodec : public Codec
{
public:
    Ipv6DSTOptsCodec() : Codec(CD_DSTOPTS_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};

struct IP6Dest
{
    IpProtocol ip6dest_nxt;
    uint8_t ip6dest_len;
    /* options follow */
    uint8_t ip6dest_pad[6];
};
} // anonymous namespace

bool Ipv6DSTOptsCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    const IP6Dest* const dsthdr = reinterpret_cast<const IP6Dest*>(raw.data);

    if (raw.len < sizeof(IP6Dest))
    {
        codec_event(codec, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    if ( SnortConfig::get_conf()->hit_ip6_maxopts(codec.ip6_extension_count) )
        codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR);

    if (dsthdr->ip6dest_nxt == IpProtocol::ROUTING)
        codec_event(codec, DECODE_IPV6_DSTOPTS_WITH_ROUTING);

    codec.lyr_len = sizeof(IP6Dest) + (dsthdr->ip6dest_len << 3);

    if (codec.lyr_len > raw.len)
    {
        codec_event(codec, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    codec.proto_bits |= PROTO_BIT__IP6_EXT;
    codec.ip6_extension_count++;
    codec.next_prot_id = (ProtocolId)dsthdr->ip6dest_nxt;
    codec.ip6_csum_proto = dsthdr->ip6dest_nxt;

    // must be called AFTER setting next_prot_id
    CheckIPv6ExtensionOrder(codec, IpProtocol::DSTOPTS);

    if ( CheckIPV6HopOptions(raw, codec))
        return true;
    return false;
}

void Ipv6DSTOptsCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.push_back(ProtocolId::DSTOPTS); }

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new Ipv6DSTOptsCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi ipv6_dstopts_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_DSTOPTS_NAME,
        CD_DSTOPTS_HELP,
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
const BaseApi* cd_dstopts[] =
#endif
{
    &ipv6_dstopts_api.base,
    nullptr
};

