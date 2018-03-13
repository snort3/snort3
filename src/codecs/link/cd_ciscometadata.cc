//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

struct CiscoMetaDataHdr
{
    uint8_t version; // This must be 1
    uint8_t length; //This is the header size in bytes / 8
};

struct CiscoMetaDataOpt
{
    uint16_t opt_len_type;  // 3-bit length + 13-bit type. Length of 0 = 4. Type must be 1.
    uint16_t sgt;           // Can be any value except 0xFFFF
};

constexpr uint8_t CISCO_META_OPT_LEN_SHIFT = 4;
constexpr uint16_t CISCO_META_OPT_TYPE_SGT = 1;
constexpr uint16_t CISCO_META_OPT_TYPE_MASK = 0x1FFF; //mask opt_len_type to get option type
} // namespace

void CiscoMetaDataCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.push_back(ProtocolId::ETHERTYPE_CISCO_META); }

bool CiscoMetaDataCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if (raw.len < sizeof(CiscoMetaDataHdr))
    {
        codec_event(codec, DECODE_CISCO_META_HDR_TRUNC);
        return false;
    }

    const CiscoMetaDataHdr* const cmdh =
        reinterpret_cast<const CiscoMetaDataHdr*>(raw.data);
    uint32_t cmdh_rem_len = cmdh->length << 3;

    if ( (raw.len < cmdh_rem_len) || (cmdh_rem_len == 0) )
    {
        codec_event(codec, DECODE_CISCO_META_HDR_TRUNC);
        return false;
    }

    const CiscoMetaDataOpt* cmd_options =
        reinterpret_cast<const CiscoMetaDataOpt*>(raw.data + sizeof(CiscoMetaDataHdr));
    // validate options, lengths, and SGTs
    cmdh_rem_len -= sizeof(CiscoMetaDataHdr) + sizeof(uint16_t); //2 octets for ethertype
    if(cmdh_rem_len == 0)
        cmd_options = nullptr;

    for(int i = 0; cmdh_rem_len > 0; i++)
    {
        // Top 3 bits (length) must be equal to 0 or 4
        // Bottom 13 bits (type) must be 1 to indicate SGT
        const CiscoMetaDataOpt* opt = &cmd_options[i];
        uint16_t len = ntohs(opt->opt_len_type) >> CISCO_META_OPT_LEN_SHIFT;
        uint16_t type = ntohs(opt->opt_len_type) & CISCO_META_OPT_TYPE_MASK;

        // 0 indicates 4 octets
        if(len != 0 && len != 4)
        {
            codec_event(codec, DECODE_CISCO_META_HDR_OPT_LEN);
            return false;
        }

        if(type != CISCO_META_OPT_TYPE_SGT)
        {
            codec_event(codec, DECODE_CISCO_META_HDR_OPT_TYPE);
            return false;
        }

        /* Tag value 0xFFFF is invalid */
        if(opt->sgt == 0xFFFF)
        {
            codec_event(codec, DECODE_CISCO_META_HDR_SGT);
            return false;
        }
        cmdh_rem_len -= sizeof(CiscoMetaDataOpt);
    }

    codec.lyr_len = cmdh->length << 3;

    //The last 2 octets of the header will be the real ethtype
    codec.next_prot_id = static_cast<ProtocolId>
        (ntohs(*((const uint16_t*)(raw.data + codec.lyr_len - sizeof(uint16_t)))));

    codec.codec_flags |= CODEC_ETHER_NEXT;
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

