//--------------------------------------------------------------------------
// Copyright (C) 2016-2019 Cisco and/or its affiliates. All rights reserved.
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
#include "log/messages.h"
#include "protocols/cisco_meta_data.h"
#include "protocols/layer.h"

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
    { DECODE_CISCO_META_HDR_SGT, "invalid Cisco Metadata SGT" },
    { 0, nullptr }
};

class CiscoMetaDataModule : public CodecModule
{
public:
    CiscoMetaDataModule() : CodecModule(CD_CISCOMETADATA_NAME, CD_CISCOMETADATA_HELP) { }

    const RuleMap* get_rules() const override
    { return ciscometadata_rules; }
};

class CiscoMetaDataCodec : public Codec
{
public:
    CiscoMetaDataCodec() : Codec(CD_CISCOMETADATA_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};

constexpr uint8_t CISCO_META_OPT_LEN_SHIFT = 4;
constexpr uint16_t CISCO_META_OPT_TYPE_SGT = 1;
constexpr uint16_t CISCO_META_OPT_TYPE_MASK = 0x1FFF; //mask opt_len_type to get option type
// Currently we only support one CiscoMetaDataHdr which is size of 1 byte.
constexpr uint8_t SUPPORTED_HDR_LEN = 1;
} // namespace

void CiscoMetaDataCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.emplace_back(ProtocolId::ETHERTYPE_CISCO_META); }

bool CiscoMetaDataCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    uint16_t len;
    uint16_t type;

    /* 2 octets for ethertype + 2 octets for CiscoMetaDataHdr
     * + 4 octets for CiscoMetaDataOpt 
     */
    uint32_t total_len = (sizeof(uint16_t)
                        + sizeof(cisco_meta_data::CiscoMetaDataHdr)
                        + sizeof(cisco_meta_data::CiscoMetaDataOpt));

    if (raw.len < total_len)
    {
        codec_event(codec, DECODE_CISCO_META_HDR_TRUNC);
        return false;
    }

    const cisco_meta_data::CiscoMetaDataHdr* const cmdh =
        reinterpret_cast<const cisco_meta_data::CiscoMetaDataHdr*>(raw.data);

    if (SUPPORTED_HDR_LEN != cmdh->length)
    {
        codec_event(codec, DECODE_CISCO_META_HDR_TRUNC);
        return false;
    }

    const cisco_meta_data::CiscoMetaDataOpt* cmd_option =
        reinterpret_cast<const cisco_meta_data::CiscoMetaDataOpt*>(raw.data
        + sizeof(cisco_meta_data::CiscoMetaDataHdr));

    // Top 3 bits (length) must be equal to 0
    // Bottom 13 bits (type) must be 1 to indicate SGT
    len = ntohs(cmd_option->opt_len_type) >> CISCO_META_OPT_LEN_SHIFT;
    type = ntohs(cmd_option->opt_len_type) & CISCO_META_OPT_TYPE_MASK;

    // 0 indicates 4 octets which is sizeof(CiscoMetaDataOpt)
    if (len != 0)
    {
        codec_event(codec, DECODE_CISCO_META_HDR_OPT_LEN);
        return false;
    }

    if (type != CISCO_META_OPT_TYPE_SGT)
    {
        codec_event(codec, DECODE_CISCO_META_HDR_OPT_TYPE);
        return false;
    }

    /* Tag value 0xFFFF is invalid */
    if (cmd_option->sgt == 0xFFFF)
    {
        codec_event(codec, DECODE_CISCO_META_HDR_SGT);
        return false;
    }

#ifdef REG_TEST
    LogMessage("Value of sgt %d\n", ntohs(cmd_option->sgt));
#endif

    codec.lyr_len = total_len;

    //The last 2 octets of the header will be the real ethtype
    codec.next_prot_id = static_cast<ProtocolId>
        (ntohs(*((const uint16_t*)(raw.data + codec.lyr_len - sizeof(uint16_t)))));

    codec.codec_flags |= CODEC_ETHER_NEXT;
    codec.proto_bits  |= PROTO_BIT__CISCO_META_DATA;

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

