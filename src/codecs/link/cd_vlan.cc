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
// cd_vlan.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/text_log.h"
#include "protocols/vlan.h"

using namespace snort;

#define CD_VLAN_NAME "vlan"
#define CD_VLAN_HELP "support for local area network"

namespace
{
static const RuleMap vlan_rules[] =
{
    { DECODE_BAD_VLAN, "bad VLAN frame" },
    { 0, nullptr }
};

class VlanModule : public CodecModule
{
public:
    VlanModule() : CodecModule(CD_VLAN_NAME, CD_VLAN_HELP) { }

    const RuleMap* get_rules() const override
    { return vlan_rules; }
};

class VlanCodec : public Codec
{
public:
    VlanCodec() : Codec(CD_VLAN_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
};

constexpr unsigned int ETHERNET_MAX_LEN_ENCAP = 1518;    /* 802.3 (+LLC) or ether II ? */
} // namespace

void VlanCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.push_back(ProtocolId::ETHERTYPE_8021Q);
    v.push_back(ProtocolId::ETHERTYPE_8021AD);
    v.push_back(ProtocolId::ETHERTYPE_QINQ_NS1);
    v.push_back(ProtocolId::ETHERTYPE_QINQ_NS2);
}

bool VlanCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if (raw.len < sizeof(vlan::VlanTagHdr))
    {
        codec_event(codec, DECODE_BAD_VLAN);
        return false;
    }

    const vlan::VlanTagHdr* const vh =
        reinterpret_cast<const vlan::VlanTagHdr*>(raw.data);

    const uint16_t proto = vh->proto();

    /* check to see if we've got an encapsulated LLC layer
     * http://www.geocities.com/billalexander/ethernet.html
     */
    if (proto <= ETHERNET_MAX_LEN_ENCAP)
        codec.next_prot_id = ProtocolId::ETHERNET_LLC;
    else
        codec.next_prot_id = (ProtocolId)proto;

    // Vlan IDs 0 and 4095 are reserved.
    const uint16_t vid = vh->vid();
    if (vid == 0 || vid == 4095)
        codec_event(codec, DECODE_BAD_VLAN);

    codec.lyr_len = sizeof(vlan::VlanTagHdr);
    codec.proto_bits |= PROTO_BIT__VLAN;
    return true;
}

void VlanCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*lyr_len*/)
{
    const vlan::VlanTagHdr* const vh = reinterpret_cast<const vlan::VlanTagHdr*>(raw_pkt);
    const uint16_t proto = ntohs(vh->vth_proto);
    const uint16_t vid = vh->vid();
    const uint16_t priority = vh->priority();

    TextLog_Print(text_log, "Priority:%d(0x%X) CFI:%d "
        "Vlan_ID:%d(0x%04X)",
        priority, priority,
        vh->cfi(), vid, vid);

    if (proto <= ETHERNET_MAX_LEN_ENCAP)
        TextLog_Print(text_log, "  Len:0x%04X", proto);
    else
        TextLog_Print(text_log, "  Next:0x%04X", proto);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new VlanModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new VlanCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi vlan_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_VLAN_NAME,
        CD_VLAN_HELP,
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
const BaseApi* cd_vlan[] =
#endif
{
    &vlan_api.base,
    nullptr
};

