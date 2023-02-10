//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include <iomanip>
#include <sstream>
#include <unordered_set>
#include <vector>

#include <daq.h>

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

static const char* default_tpids = "0x9100 0x9200";

static const Parameter vlan_params[] =
{
    { "extra_tpid_ether_types", Parameter::PT_INT_LIST, "65535", default_tpids,
      "set non-standard QinQ ether types" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class VlanModule : public BaseCodecModule
{
public:
    VlanModule() : BaseCodecModule(CD_VLAN_NAME, CD_VLAN_HELP, vlan_params) { }

    bool set(const char*, Value&, SnortConfig*) override;

    const RuleMap* get_rules() const override
    { return vlan_rules; }

    const char* get_tpids() const
    { return tpids.c_str(); }

private:
    std::string tpids;
};

bool VlanModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("extra_tpid_ether_types"));
    tpids = v.get_string();
    return true;
}

class VlanCodec : public Codec
{
public:
    VlanCodec(const char* s) : Codec(CD_VLAN_NAME)
    { tpids = s; }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len, EncState&, Buffer&, Flow*) override;

private:
    std::string tpids;
};

constexpr unsigned int ETHERNET_MAX_LEN_ENCAP = 1518;    /* 802.3 (+LLC) or ether II ? */
} // namespace

void VlanCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    std::unordered_set<ProtocolId> id_set;
    id_set.insert(ProtocolId::ETHERTYPE_8021Q);
    id_set.insert(ProtocolId::ETHERTYPE_8021AD);

    std::stringstream ss(tpids);
    ss >> std::setbase(0);
    int val;

    while ( ss >> val )
        id_set.insert((ProtocolId)val);

    for ( auto id : id_set )
        v.emplace_back(id);
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

    codec.lyr_len = sizeof(vlan::VlanTagHdr);

    const DAQ_PktHdr_t* pkth = daq_msg_get_pkthdr(raw.daq_msg);
    if (pkth->flags & DAQ_PKT_FLAG_IGNORE_VLAN)
        return true;

    // Vlan IDs 0 and 4095 are reserved.
    const uint16_t vid = vh->vid();
    if (vid == 0 || vid == 4095)
        codec_event(codec, DECODE_BAD_VLAN);

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

bool VlanCodec::encode(const uint8_t* const raw_in, const uint16_t raw_len, EncState& enc,
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
{ return new VlanModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module* m)
{
    VlanModule* mod = (VlanModule*)m;
    return new VlanCodec(mod ? mod->get_tpids() : default_tpids);
}

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

