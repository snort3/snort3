//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
// cd_teredo.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "main/snort_config.h"
#include "packet_io/active.h"
#include "protocols/teredo.h"

using namespace snort;

#define CD_TEREDO_NAME "teredo"
#define CD_TEREDO_HELP "support for teredo"

namespace
{
class TeredoCodec : public Codec
{
public:
    TeredoCodec() : Codec(CD_TEREDO_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};
} // anonymous namespace

void TeredoCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.push_back(ProtocolId::TEREDO);
}

bool TeredoCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    const uint8_t* raw_pkt = raw.data;

    if ( raw.len < teredo::MIN_HDR_LEN )
        return false;

    /* Decode indicators. If both are present, Auth always comes before Origin. */
    if ( ntohs(*(const uint16_t*)raw_pkt) == teredo::INDICATOR_AUTH )
    {
        if ( raw.len < teredo::INDICATOR_AUTH_MIN_LEN )
            return false;

        uint8_t client_id_length = *(raw_pkt + 2);
        uint8_t auth_data_length = *(raw_pkt + 3);

        if (raw.len < (uint32_t)(teredo::INDICATOR_AUTH_MIN_LEN + client_id_length +
            auth_data_length))
            return false;

        raw_pkt += (teredo::INDICATOR_AUTH_MIN_LEN + client_id_length + auth_data_length);
        codec.lyr_len = (teredo::INDICATOR_AUTH_MIN_LEN + client_id_length + auth_data_length);
    }

    if ( ntohs(*(const uint16_t*)raw_pkt) == teredo::INDICATOR_ORIGIN )
    {
        if ( raw.len < teredo::INDICATOR_ORIGIN_LEN )
            return false;

        raw_pkt += teredo::INDICATOR_ORIGIN_LEN;
        codec.lyr_len += teredo::INDICATOR_ORIGIN_LEN;
    }

    /* If this is an IPv6 datagram, the first 4 bits will be the number 6. */
    if ( ((*raw_pkt & 0xF0) >> 4) == 6 )
    {
        codec.proto_bits |= PROTO_BIT__TEREDO;
        codec.codec_flags |= CODEC_TEREDO_SEEN;  // for ipv6 codec

        if ( SnortConfig::tunnel_bypass_enabled(TUNNEL_TEREDO) )
            Active::set_tunnel_bypass();

        if ( (!teredo::is_teredo_port(snort.sp)) && (!teredo::is_teredo_port(snort.dp)) )
            codec.codec_flags |= CODEC_ENCAP_LAYER;

        codec.next_prot_id = ProtocolId::IPV6;
        codec.codec_flags |= CODEC_NON_IP_TUNNEL;
        return true;
    }

    return false;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new TeredoCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi teredo_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_TEREDO_NAME,
        CD_TEREDO_HELP,
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
const BaseApi* cd_teredo[] =
#endif
{
    &teredo_api.base,
    nullptr
};

