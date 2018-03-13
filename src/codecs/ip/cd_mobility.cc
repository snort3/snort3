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
// cd_mobility.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "main/snort_config.h"

using namespace snort;

// yes, macros are necessary. The API and class constructor require different strings.
#define CD_MOBILE_NAME "ipv6_mobility"
#define CD_MOBILE_HELP "support for mobility"

namespace
{
class MobilityCodec : public Codec
{
public:
    MobilityCodec() : Codec(CD_MOBILE_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>&) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};

struct MobileIPV6Header  // RFC 6275
{
    IpProtocol payload_proto;
    uint8_t header_len;
    uint8_t mh_type;
    uint8_t reserved;
    uint16_t checksum;
};
} // namespace

void MobilityCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.push_back(ProtocolId::MOBILITY_IPV6);
}

bool MobilityCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    const MobileIPV6Header* const mip6 = reinterpret_cast<const MobileIPV6Header*>(raw.data);
    if ( SnortConfig::get_conf()->hit_ip6_maxopts(codec.ip6_extension_count) )
    {
        codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR);
        return false;
    }

    codec.lyr_len = ip::MIN_EXT_LEN + (mip6->header_len << 3);
    if (codec.lyr_len > raw.len)
    {
        codec_event(codec, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    codec.proto_bits |= PROTO_BIT__IP6_EXT; // check ip proto rules against this layer
    codec.ip6_extension_count++;
    // RFC 6275, 6.1.1 and 9.2, payload protocol must be IPPROTO_NONE (59 decimal)
    if (mip6->payload_proto != IpProtocol::NONEXT)
        codec_event(codec, DECODE_MIPV6_BAD_PAYLOAD_PROTO);

    codec.next_prot_id = (ProtocolId)mip6->payload_proto;
    codec.ip6_csum_proto = mip6->payload_proto;

    // must be called AFTER setting next_prot_id
    // Mobility Header must always be the last header in the header chain of an IPv6 packet
    CheckIPv6ExtensionOrder(codec, IpProtocol::MOBILITY_IPV6);
    
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new MobilityCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi mobility_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_MOBILE_NAME,
        CD_MOBILE_HELP,
        nullptr,
        nullptr
    },
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ctor,
    dtor,
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* cd_mobility[] =
#endif
{
    &mobility_api.base,
    nullptr
};

