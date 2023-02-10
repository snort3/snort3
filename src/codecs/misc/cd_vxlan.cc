//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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
// cd_vxlan.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "packet_io/active.h"

using namespace snort;

#define CD_VXLAN_NAME "vxlan"
#define CD_VXLAN_HELP "support for Virtual Extensible LAN"

namespace
{
class VxlanCodec : public Codec
{
public:
    VxlanCodec() : Codec(CD_VXLAN_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
};

struct VXLANHdr
{
    uint8_t flags;
    uint8_t reserved_1[3];
    uint8_t vni[3]; //VXLAN network id
    uint8_t reserved_2;
};
constexpr uint16_t VXLAN_MIN_HDR_LEN = 8;
} // anonymous namespace

void VxlanCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.push_back(ProtocolId::VXLAN);
}

bool VxlanCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if ( raw.len < VXLAN_MIN_HDR_LEN )
        return false;

    const VXLANHdr* const hdr = reinterpret_cast<const VXLANHdr*>(raw.data);

    if ( hdr->flags != 0x08 )
        return false;

    if ( codec.conf->tunnel_bypass_enabled(TUNNEL_VXLAN) )
        codec.tunnel_bypass = true;

    codec.lyr_len = VXLAN_MIN_HDR_LEN;
    codec.proto_bits |= PROTO_BIT__VXLAN;
    codec.next_prot_id = ProtocolId::ETHERNET_802_3;
    codec.codec_flags |= CODEC_NON_IP_TUNNEL;

    return true;
}

void VxlanCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*lyr_len*/)
{
    const VXLANHdr* const hdr = reinterpret_cast<const VXLANHdr*>(raw_pkt);
    uint32_t vni = ( hdr->vni[0] << 16 ) | ( hdr->vni[1] << 8 ) | hdr->vni[2];
    TextLog_Print(text_log, "network identifier: %u", vni);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new VxlanCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi vxlan_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_VXLAN_NAME,
        CD_VXLAN_HELP,
        nullptr,
        nullptr
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
const BaseApi* cd_vxlan[] =
#endif
{
    &vxlan_api.base,
    nullptr
};

