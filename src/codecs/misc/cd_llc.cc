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
// cd_llc.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/text_log.h"

using namespace snort;

#define LLC_NAME "llc"
#define LLC_HELP "support for logical link control"

namespace
{
static const RuleMap llc_rules[] =
{
    { DECODE_BAD_LLC_HEADER, "bad LLC header" },
    { DECODE_BAD_LLC_OTHER, "bad extra LLC info"},
    { 0, nullptr }
};

class LlcModule : public CodecModule
{
public:
    LlcModule() : CodecModule(LLC_NAME, LLC_HELP) {}

    const RuleMap* get_rules() const override
    { return llc_rules; }
};

class LlcCodec : public Codec
{
public:
    LlcCodec() : Codec(LLC_NAME) { }

    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
    void get_protocol_ids(std::vector<ProtocolId>&) override;
};

struct EthLlc
{
    uint8_t dsap;
    uint8_t ssap;
    uint8_t ctrl;
};

struct EthLlcOther
{
    uint8_t org_code[3];
    uint8_t proto_id[2];

    ProtocolId proto() const
    {
#ifdef __GNUC__
        // fixing the type_punned pointer problem
        const uint8_t* tmp1 = &proto_id[0];
        const uint16_t* const tmp2 = reinterpret_cast<const uint16_t*>(tmp1);
        return (ProtocolId)ntohs(*tmp2);
#else
        return (ProtocolId)ntohs(*((uint16_t*)(&proto_id[0])));
#endif
    }
};

#define ETH_DSAP_SNA 0x08    /* SNA */
#define ETH_SSAP_SNA 0x00    /* SNA */
#define ETH_DSAP_STP 0x42    /* Spanning Tree Protocol */
#define ETH_SSAP_STP 0x42    /* Spanning Tree Protocol */
#define ETH_DSAP_IP  0xaa    /* IP */
#define ETH_SSAP_IP  0xaa    /* IP */

#define ETH_ORG_CODE_ETHR 0x000000    /* Encapsulated Ethernet */
#define ETH_ORG_CODE_CDP  0x00000c    /* Cisco Discovery Proto */
} // namespace

void LlcCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.push_back(ProtocolId::ETHERNET_LLC); }

bool LlcCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if (raw.len < sizeof(EthLlc))
    {
        // FIXIT-L need a better alert for llc len
        codec_event(codec, DECODE_BAD_LLC_HEADER);
        return false;
    }

    const EthLlc* ehllc = reinterpret_cast<const EthLlc*>(raw.data);

    if (ehllc->dsap == ETH_DSAP_IP &&
        ehllc->ssap == ETH_SSAP_IP)
    {
        if (raw.len <  sizeof(EthLlc) + sizeof(EthLlcOther))
        {
            codec_event(codec, DECODE_BAD_LLC_OTHER);
            return false;
        }

        const EthLlcOther* ehllcother = reinterpret_cast<const EthLlcOther*>(raw.data +
            sizeof(EthLlc));
        
        if (ehllcother->org_code[0] == 0 &&
            ehllcother->org_code[1] == 0 &&
            ehllcother->org_code[2] == 0)
        {
            codec.lyr_len = sizeof(EthLlc) + sizeof(EthLlcOther);
            codec.next_prot_id = ehllcother->proto();
            codec.codec_flags |= CODEC_ETHER_NEXT;
        }
    }

    return true;
}

void LlcCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*lyr_len*/)
{
    const EthLlc* ehllc = reinterpret_cast<const EthLlc*>(raw_pkt);

    TextLog_Print(text_log, "DSAP:0x%X SSAP:0x%X CTRL:0x%X",
        ehllc->dsap, ehllc->ssap, ehllc->ctrl);

    // Assuming that if these three conditions are met, this is SNAP.
    if (ehllc->dsap == ETH_DSAP_IP &&
        ehllc->ssap == ETH_SSAP_IP)
    {
        const EthLlcOther* other = reinterpret_cast<const EthLlcOther*>(raw_pkt + sizeof(EthLlc));
        const ProtocolId proto = other->proto();

        TextLog_Print(text_log, " ORG:0x%02X%02X%02X PROTO:0x%04X",
            other->org_code[0], other->org_code[1], other->org_code[2],
            proto);
    }
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static Module* mod_ctor()
{ return new LlcModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new LlcCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi llc_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        LLC_NAME,
        LLC_HELP,
        mod_ctor,
        mod_dtor
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
const BaseApi* cd_llc[] =
#endif
{
    &llc_api.base,
    nullptr
};

