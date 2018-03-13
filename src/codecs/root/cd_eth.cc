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
// cd_eth.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sfbpf_dlt.h>

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "protocols/eth.h"
#include "protocols/packet_manager.h"

using namespace snort;

#define CD_ETH_NAME "eth"
#define CD_ETH_HELP_STR "support for ethernet protocol"
#define CD_ETH_HELP ADD_DLT(ADD_DLT(CD_ETH_HELP_STR, DLT_EN10MB), DLT_PPP_ETHER)

namespace
{
static const RuleMap eth_rules[] =
{
    { DECODE_ETH_HDR_TRUNC, "truncated ethernet header" },
    { 0, nullptr }
};

class EthModule : public CodecModule
{
public:
    EthModule() : CodecModule(CD_ETH_NAME, CD_ETH_HELP) { }

    const RuleMap* get_rules() const override
    { return eth_rules; }
};

class EthCodec : public Codec
{
public:
    EthCodec() : Codec(CD_ETH_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>&) override;
    void get_data_link_type(std::vector<int>&) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&, Flow*) override;
    void format(bool reverse, uint8_t* raw_pkt, DecodeData& snort) override;
    void update(const ip::IpApi&, const EncodeFlags, uint8_t* raw_pkt,
        uint16_t lyr_len, uint32_t& updated_len) override;
};
} // namespace

void EthCodec::get_data_link_type(std::vector<int>& v)
{
    v.push_back(DLT_PPP_ETHER);
    v.push_back(DLT_EN10MB);
}

void EthCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.push_back(ProtocolId::ETHERNET_802_3);
}

bool EthCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if (raw.len < eth::ETH_HEADER_LEN)
    {
        codec_event(codec, DECODE_ETH_HDR_TRUNC);
        return false;
    }

    /* lay the ethernet structure over the packet data */
    const eth::EtherHdr* eh = reinterpret_cast<const eth::EtherHdr*>(raw.data);

    ProtocolId next_prot = eh->ethertype();
    if ( to_utype(next_prot) <= to_utype(ProtocolId::ETHERTYPE_MINIMUM) )
    {
        codec.next_prot_id = ProtocolId::ETHERNET_LLC;
        codec.lyr_len = eth::ETH_HEADER_LEN;
        codec.proto_bits |= PROTO_BIT__ETH;
    }
    else if ( next_prot == ProtocolId::ETHERTYPE_FPATH )
    {
        /*  If this is FabricPath, the first 16 bytes are FabricPath data
         *  rather than Ethernet data.  So, set the length to zero and
         *  and decode this FabricPath data. Then, FabricPath will send the decoder
         *  right back to this Ethernet function.
         */
        codec.next_prot_id = next_prot;
        codec.lyr_len = 0;
    }
    else
    {
        codec.proto_bits |= PROTO_BIT__ETH;
        codec.lyr_len = eth::ETH_HEADER_LEN;
        codec.next_prot_id = next_prot;
    }

    return true;
}

void EthCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*len*/)
{
    const eth::EtherHdr* eh = reinterpret_cast<const eth::EtherHdr*>(raw_pkt);

    /* src addr */
    TextLog_Print(text_log, "%02X:%02X:%02X:%02X:%02X:%02X -> ", eh->ether_src[0],
        eh->ether_src[1], eh->ether_src[2], eh->ether_src[3],
        eh->ether_src[4], eh->ether_src[5]);

    /* dest addr */
    TextLog_Print(text_log, "%02X:%02X:%02X:%02X:%02X:%02X", eh->ether_dst[0],
        eh->ether_dst[1], eh->ether_dst[2], eh->ether_dst[3],
        eh->ether_dst[4], eh->ether_dst[5]);

    const ProtocolId prot_id = eh->ethertype();

    if (to_utype(prot_id) <= to_utype(ProtocolId::ETHERTYPE_MINIMUM))
        TextLog_Print(text_log, "  len:0x%04X", prot_id);
    else
        TextLog_Print(text_log, "  type:0x%04X", prot_id);
}

//-------------------------------------------------------------------------
// ethernet
//-------------------------------------------------------------------------

bool EthCodec::encode(const uint8_t* const raw_in, const uint16_t /*raw_len*/,
    EncState& enc, Buffer& buf, Flow*)
{
    const eth::EtherHdr* hi = reinterpret_cast<const eth::EtherHdr*>(raw_in);

    if (hi->ethertype() == ProtocolId::ETHERTYPE_FPATH)
        return true;

    // not raw ip -> encode layer 2
    bool raw = ( enc.flags & ENC_FLAG_RAW );

    if ( !raw || (buf.size() != 0) )
    {
        // we get here for outer-most layer when not raw ip
        // we also get here for any encapsulated ethernet layer.
        if ( !buf.allocate(eth::ETH_HEADER_LEN) )
            return false;

        eth::EtherHdr* ho = reinterpret_cast<eth::EtherHdr*>(buf.data());
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

void EthCodec::format(bool reverse, uint8_t* raw_pkt, DecodeData&)
{
    eth::EtherHdr* ch = reinterpret_cast<eth::EtherHdr*>(raw_pkt);

    // If the ethertype is FabricPath, then this is not Ethernet Data.
    if ( reverse &&  (ch->ethertype() != ProtocolId::ETHERTYPE_FPATH) )
    {
        uint8_t tmp_addr[6];

        memcpy(tmp_addr, ch->ether_dst, sizeof(ch->ether_dst));
        memcpy(ch->ether_dst, ch->ether_src, sizeof(ch->ether_src));
        memcpy(ch->ether_src, tmp_addr, sizeof(ch->ether_src));
    }
}

void EthCodec::update(const ip::IpApi&, const EncodeFlags, uint8_t* raw_pkt,
    uint16_t lyr_len, uint32_t& updated_len)
{
    const eth::EtherHdr* const eth = reinterpret_cast<eth::EtherHdr*>(raw_pkt);

    if ( eth->ethertype() != ProtocolId::ETHERTYPE_FPATH )
        updated_len += lyr_len;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new EthModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new EthCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi eth_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_ETH_NAME,
        CD_ETH_HELP,
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

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* cd_eth[] =
#endif
{
    &eth_api.base,
    nullptr
};

