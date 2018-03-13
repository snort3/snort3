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
// cd_erspan3.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"

using namespace snort;

#define CD_ERSPAN3_NAME "erspan3"
#define CD_ERSPAN3_HELP "support for encapsulated remote switched port analyzer - type 3"

namespace
{
static const RuleMap erspan3_rules[] =
{
    { DECODE_ERSPAN3_DGRAM_LT_HDR, "captured < ERSpan type3 header length" },
    { 0, nullptr }
};

class Erspan3Module : public CodecModule
{
public:
    Erspan3Module() : CodecModule(CD_ERSPAN3_NAME, CD_ERSPAN3_HELP) { }

    const RuleMap* get_rules() const override
    { return erspan3_rules; }
};

class Erspan3Codec : public Codec
{
public:
    Erspan3Codec() : Codec(CD_ERSPAN3_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};

struct ERSpanType3Hdr
{
    uint16_t ver_vlan;
    uint16_t flags_spanId;
    uint32_t timestamp;
    uint16_t pad0;
    uint16_t pad1;
    uint32_t pad2;
    uint32_t pad3;

    inline uint16_t version() const
    { return ntohs(ver_vlan) >> 12; }
};

} // anonymous namespace

void Erspan3Codec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.push_back(ProtocolId::ETHERTYPE_ERSPAN_TYPE3); }

bool Erspan3Codec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    const ERSpanType3Hdr* const erSpan3Hdr =
        reinterpret_cast<const ERSpanType3Hdr*>(raw.data);

    if (raw.len < sizeof(ERSpanType3Hdr))
    {
        codec_event(codec, DECODE_ERSPAN3_DGRAM_LT_HDR);
        return false;
    }

    // Check that this is in fact ERSpan Type 3.
    if (erSpan3Hdr->version() != 0x02) /* Type 3 == version 0x02 */
    {
        codec_event(codec, DECODE_ERSPAN_HDR_VERSION_MISMATCH);
        return false;
    }

    codec.next_prot_id = ProtocolId::ETHERTYPE_TRANS_ETHER_BRIDGING;
    codec.lyr_len = sizeof(ERSpanType3Hdr);
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new Erspan3Module; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new Erspan3Codec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi erspan3_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_ERSPAN3_NAME,
        CD_ERSPAN3_HELP,
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
const BaseApi* cd_erspan3[] =
#endif
{
    &erspan3_api.base,
    nullptr
};

