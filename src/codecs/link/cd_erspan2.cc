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
// cd_erspan2.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"

using namespace snort;

#define CD_ERSPAN2_NAME "erspan2"
#define CD_ERSPAN2_HELP "support for encapsulated remote switched port analyzer - type 2"

namespace
{
static const RuleMap erspan2_rules[] =
{
    { DECODE_ERSPAN_HDR_VERSION_MISMATCH, "ERSpan header version mismatch" },
    { DECODE_ERSPAN2_DGRAM_LT_HDR, "captured length < ERSpan type2 header length" },
    { 0, nullptr }
};

class Erspan2Module : public CodecModule
{
public:
    Erspan2Module() : CodecModule(CD_ERSPAN2_NAME, CD_ERSPAN2_HELP) { }

    const RuleMap* get_rules() const override
    { return erspan2_rules; }
};

class Erspan2Codec : public Codec
{
public:
    Erspan2Codec() : Codec(CD_ERSPAN2_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};

struct ERSpanType2Hdr
{
    uint16_t ver_vlan;
    uint16_t flags_spanId;
    uint32_t pad;

    uint16_t version() const
    { return ntohs(ver_vlan) >> 12; }
};

} // namespace

void Erspan2Codec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.push_back(ProtocolId::ETHERTYPE_ERSPAN_TYPE2); }

bool Erspan2Codec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    const ERSpanType2Hdr* const erSpan2Hdr =
        reinterpret_cast<const ERSpanType2Hdr*>(raw.data);

    if (raw.len < sizeof(ERSpanType2Hdr))
    {
        codec_event(codec, DECODE_ERSPAN2_DGRAM_LT_HDR);
        return false;
    }

    /* Check that this is in fact ERSpan Type 2.
     */
    if (erSpan2Hdr->version() != 0x01) /* Type 2 == version 0x01 */
    {
        codec_event(codec, DECODE_ERSPAN_HDR_VERSION_MISMATCH);
        return false;
    }

    codec.lyr_len = sizeof(ERSpanType2Hdr);
    codec.next_prot_id = ProtocolId::ETHERTYPE_TRANS_ETHER_BRIDGING;
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new Erspan2Module; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new Erspan2Codec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi erspan2_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_ERSPAN2_NAME,
        CD_ERSPAN2_HELP,
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
const BaseApi* cd_erspan2[] =
#endif
{
    &erspan2_api.base,
    nullptr
};

