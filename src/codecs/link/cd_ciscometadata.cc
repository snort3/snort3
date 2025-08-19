//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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
// cd_ciscometadata.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/text_log.h"
#include "protocols/cisco_meta_data.h"

using namespace snort;

#define CD_CISCOMETADATA_NAME "ciscometadata"
#define CD_CISCOMETADATA_HELP "support for cisco metadata"

namespace
{
static const RuleMap ciscometadata_rules[] =
{
    { DECODE_CISCO_META_HDR_TRUNC, "truncated Cisco Metadata header" },
    { DECODE_CISCO_META_HDR_OPT_LEN, "invalid Cisco Metadata option length" },
    { DECODE_CISCO_META_HDR_OPT_TYPE, "invalid Cisco Metadata option type" },
    { DECODE_CISCO_META_HDR_SGT, "invalid Cisco Metadata security group tag" },
    { 0, nullptr }
};

static const PegInfo ciscometadata_pegs[] =
{
    { CountType::SUM, "truncated_hdr", "total truncated Cisco Metadata headers" },
    { CountType::SUM, "invalid_hdr_ver", "total invalid Cisco Metadata header versions" },
    { CountType::SUM, "invalid_hdr_len", "total invalid Cisco Metadata header lengths" },
    { CountType::SUM, "invalid_opt_len", "total invalid Cisco Metadata option lengths" },
    { CountType::SUM, "invalid_opt_type", "total invalid Cisco Metadata option types" },
    { CountType::SUM, "invalid_sgt", "total invalid Cisco Metadata security group tags" },
    { CountType::END, nullptr, nullptr }
};

struct CiscoMetaDataStats
{
    PegCount truncated_hdr;
    PegCount invalid_hdr_ver;
    PegCount invalid_hdr_len;
    PegCount invalid_opt_len;
    PegCount invalid_opt_type;
    PegCount invalid_sgt;
};
static THREAD_LOCAL CiscoMetaDataStats ciscometadata_stats;

class CiscoMetaDataModule : public BaseCodecModule
{
public:
    CiscoMetaDataModule() : BaseCodecModule(CD_CISCOMETADATA_NAME, CD_CISCOMETADATA_HELP) { }

    const RuleMap* get_rules() const override
    { return ciscometadata_rules; }

    const PegInfo* get_pegs() const override
    { return ciscometadata_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*) &ciscometadata_stats; }
};

class CiscoMetaDataCodec : public Codec
{
public:
    CiscoMetaDataCodec() : Codec(CD_CISCOMETADATA_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void log(TextLog* const, const uint8_t* raw_pkt, const uint16_t lyr_len) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len, EncState&, Buffer&, Flow*) override;
};

constexpr uint8_t CISCO_META_VALID_HDR_VER = 1;
constexpr uint8_t CISCO_META_VALID_HDR_LEN = 1;
constexpr uint16_t CISCO_META_VALID_OPT_LEN = 0;
constexpr uint8_t CISCO_META_OPT_LEN_SHIFT = 13;
constexpr uint16_t CISCO_META_OPT_TYPE_SGT = 1;
constexpr uint16_t CISCO_META_OPT_TYPE_MASK = 0x1FFF; // mask opt_len_type to get option type
} // namespace

void CiscoMetaDataCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.emplace_back(ProtocolId::ETHERTYPE_CISCO_META); }

bool CiscoMetaDataCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if (raw.len < sizeof(cisco_meta_data::CiscoMetaDataHdr))
    {
        ciscometadata_stats.truncated_hdr++;
        codec_event(codec, DECODE_CISCO_META_HDR_TRUNC);
        return false;
    }

    const cisco_meta_data::CiscoMetaDataHdr* const cmdh =
        reinterpret_cast<const cisco_meta_data::CiscoMetaDataHdr*>(raw.data);

    if (cmdh->version != CISCO_META_VALID_HDR_VER)
    {
        ciscometadata_stats.invalid_hdr_ver++;
        return false;
    }

    if (cmdh->length != CISCO_META_VALID_HDR_LEN)
    {
        ciscometadata_stats.invalid_hdr_len++;
        return false;
    }

    // Top 3 bits (length) must be equal to 0
    // Bottom 13 bits (type) must be 1 to indicate SGT
    uint16_t len = ntohs(cmdh->opt_len_type) >> CISCO_META_OPT_LEN_SHIFT;
    uint16_t type = ntohs(cmdh->opt_len_type) & CISCO_META_OPT_TYPE_MASK;

    // 0 indicates no additional options beyond SGT, which is all we support
    if (len > CISCO_META_VALID_OPT_LEN)
    {
        ciscometadata_stats.invalid_opt_len++;
        codec_event(codec, DECODE_CISCO_META_HDR_OPT_LEN);
        return false;
    }

    if (type != CISCO_META_OPT_TYPE_SGT)
    {
        ciscometadata_stats.invalid_opt_type++;
        codec_event(codec, DECODE_CISCO_META_HDR_OPT_TYPE);
        return false;
    }

    /* Tag value 0xFFFF is invalid */
    if (cmdh->sgt == 0xFFFF)
    {
        ciscometadata_stats.invalid_sgt++;
        codec_event(codec, DECODE_CISCO_META_HDR_SGT);
        return false;
    }

    codec.lyr_len = sizeof(cisco_meta_data::CiscoMetaDataHdr);

    codec.next_prot_id = static_cast<ProtocolId>(ntohs(cmdh->ether_type));

    codec.codec_flags |= CODEC_ETHER_NEXT;
    codec.proto_bits  |= PROTO_BIT__CISCO_META_DATA;

    return true;
}

void CiscoMetaDataCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*lyr_len*/)
{
    const cisco_meta_data::CiscoMetaDataHdr* const cmdh =
        reinterpret_cast<const cisco_meta_data::CiscoMetaDataHdr*>(raw_pkt);

    TextLog_Print(text_log, "Ver:%hhu  SGT:%hu  EtherNext:0x%X",
            cmdh->version, cmdh->sgt_val(), ntohs(cmdh->ether_type));
}

bool CiscoMetaDataCodec::encode(const uint8_t* const raw_in, const uint16_t raw_len, EncState& enc,
    Buffer& buf, Flow*)
{
    if (!buf.allocate(raw_len))
        return false;

    memcpy(buf.data(), raw_in, raw_len);

    enc.next_ethertype = ProtocolId::ETHERTYPE_NOT_SET;
    enc.next_proto = IpProtocol::PROTO_NOT_SET;

    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new CiscoMetaDataModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new CiscoMetaDataCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi ciscometadata_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_CISCOMETADATA_NAME,
        CD_CISCOMETADATA_HELP,
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
const BaseApi* cd_ciscometadata[] =
#endif
{
    &ciscometadata_api.base,
    nullptr
};

