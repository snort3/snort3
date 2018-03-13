//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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

// cd_pbb.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sfbpf_dlt.h>

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "protocols/packet_manager.h"

using namespace snort;

#define CD_PBB_NAME "pbb"
#define CD_PBB_HELP "support for 802.1ah protocol"

#define ETHERTYPE_8021AH 0x88E7

namespace
{
struct PbbHdr
{   
    uint32_t i_sid;
    uint8_t ether_dst[6];
    uint8_t ether_src[6];
    uint16_t ether_type;
    
    inline ProtocolId ethertype() const
    { return (ProtocolId)ntohs(ether_type); }
} __attribute__((__packed__));

static const RuleMap pbb_rules[] =
{
    // FIXIT-H need own gid
    { DECODE_ETH_HDR_TRUNC, "truncated ethernet header" },
    { 0, nullptr }
};

class PbbModule : public CodecModule
{
public:
    PbbModule() : CodecModule(CD_PBB_NAME, CD_PBB_HELP) { }

    const RuleMap* get_rules() const override
    { return pbb_rules; }
};

class PbbCodec : public Codec
{
public:
    PbbCodec() : Codec(CD_PBB_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>&) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&, Flow*) override;
    void format(bool reverse, uint8_t* raw_pkt, DecodeData& snort) override;
    void update(const ip::IpApi&, const EncodeFlags, uint8_t* raw_pkt,
        uint16_t lyr_len, uint32_t& updated_len) override;
};
} // namespace

void PbbCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.push_back((ProtocolId)ETHERTYPE_8021AH);
}

bool PbbCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if (raw.len < sizeof(PbbHdr))
    {
        codec_event(codec, DECODE_ETH_HDR_TRUNC);
        return false;
    }

    const PbbHdr* pbb = reinterpret_cast<const PbbHdr*>(raw.data);

    ProtocolId next_prot = pbb->ethertype();

    codec.proto_bits |= PROTO_BIT__ETH;
    codec.lyr_len = sizeof(PbbHdr);
    codec.next_prot_id = next_prot;

    return true;
}

void PbbCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t len)
{
    const PbbHdr* pbb = reinterpret_cast<const PbbHdr*>(raw_pkt);

    /* src addr */
    TextLog_Print(text_log, "%02X:%02X:%02X:%02X:%02X:%02X -> ", pbb->ether_src[0],
        pbb->ether_src[1], pbb->ether_src[2], pbb->ether_src[3],
        pbb->ether_src[4], pbb->ether_src[5]);

    /* dest addr */
    TextLog_Print(text_log, "%02X:%02X:%02X:%02X:%02X:%02X", pbb->ether_dst[0],
        pbb->ether_dst[1], pbb->ether_dst[2], pbb->ether_dst[3],
        pbb->ether_dst[4], pbb->ether_dst[5]);

    TextLog_Print(text_log, "  len:%hu", len);
    TextLog_Print(text_log, "  type:0x%04X", pbb->ethertype());
}

//-------------------------------------------------------------------------
// ethernet
//-------------------------------------------------------------------------

bool PbbCodec::encode(const uint8_t* const raw_in, const uint16_t /*raw_len*/,
    EncState& enc, Buffer& buf, Flow*)
{
    const PbbHdr* hi = reinterpret_cast<const PbbHdr*>(raw_in);

    // not raw ip -> encode layer 2
    bool raw = ( enc.flags & ENC_FLAG_RAW );

    if ( !raw || (buf.size() != 0) )
    {
        // we get here for outer-most layer when not raw ip
        // we also get here for any encapsulated ethernet layer.
        if ( !buf.allocate(sizeof(PbbHdr)) )
            return false;

        PbbHdr* ho = reinterpret_cast<PbbHdr*>(buf.data());
        ho->ether_type = enc.ethertype_set() ?
            htons(to_utype(enc.next_ethertype)) : hi->ether_type;

        if ( enc.forward() )
        {
            memcpy(ho->ether_src, hi->ether_src, sizeof(ho->ether_src));

            if ( SnortConfig::get_conf()->eth_dst )
                memcpy(ho->ether_dst, SnortConfig::get_conf()->eth_dst, sizeof(ho->ether_dst));
            else
                memcpy(ho->ether_dst, hi->ether_dst, sizeof(ho->ether_dst));
        }
        else
        {
            memcpy(ho->ether_src, hi->ether_dst, sizeof(ho->ether_src));

            if ( SnortConfig::get_conf()->eth_dst )
                memcpy(ho->ether_dst, SnortConfig::get_conf()->eth_dst, sizeof(ho->ether_dst));
            else
                memcpy(ho->ether_dst, hi->ether_src, sizeof(ho->ether_dst));
        }
    }

    enc.next_ethertype = ProtocolId::ETHERTYPE_NOT_SET;
    enc.next_proto = IpProtocol::PROTO_NOT_SET;
    return true;
}

void PbbCodec::format(bool reverse, uint8_t* raw_pkt, DecodeData&)
{
    PbbHdr* ch = reinterpret_cast<PbbHdr*>(raw_pkt);

    if ( reverse )
    {
        uint8_t tmp_addr[6];

        memcpy(tmp_addr, ch->ether_dst, sizeof(ch->ether_dst));
        memcpy(ch->ether_dst, ch->ether_src, sizeof(ch->ether_src));
        memcpy(ch->ether_src, tmp_addr, sizeof(ch->ether_src));
    }
}

void PbbCodec::update(const ip::IpApi&, const EncodeFlags, uint8_t*,
    uint16_t lyr_len, uint32_t& updated_len)
{
    updated_len += lyr_len;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new PbbModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new PbbCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi pbb_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_PBB_NAME,
        CD_PBB_HELP,
        mod_ctor,
        mod_dtor,
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    dtor, // dtor
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &pbb_api.base,
    nullptr
};

