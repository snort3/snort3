/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// cd_vlan.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "protocols/packet.h"
#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"
#include "protocols/vlan.h"
#include "protocols/eth.h"
#include "protocols/protocol_ids.h"
#include "codecs/sf_protocols.h"
#include "protocols/packet_manager.h"
#include "log/text_log.h"

namespace
{

#define CD_VLAN_NAME "vlan"
static const RuleMap vlan_rules[] =
{
    { DECODE_BAD_VLAN, "(" CD_VLAN_NAME ") Bad VLAN Frame" },
    { DECODE_BAD_VLAN_ETHLLC, "(" CD_VLAN_NAME ") Bad LLC header" },
    { DECODE_BAD_VLAN_OTHER, "(" CD_VLAN_NAME ") Bad Extra LLC Info" },
    { 0, nullptr }
};

class VlanModule : public DecodeModule
{
public:
    VlanModule() : DecodeModule(CD_VLAN_NAME) {}

    const RuleMap* get_rules() const
    { return vlan_rules; }
};


class VlanCodec : public Codec
{
public:
    VlanCodec() : Codec(CD_VLAN_NAME){};
    ~VlanCodec(){};

    virtual PROTO_ID get_proto_id() { return PROTO_VLAN; };
    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
    virtual void log(TextLog* const, const uint8_t* /*raw_pkt*/,
        const Packet* const);
};


constexpr unsigned int ETHERNET_MAX_LEN_ENCAP = 1518;    /* 802.3 (+LLC) or ether II ? */

} // namespace


void VlanCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_8021Q);
}


bool VlanCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    if(raw_len < sizeof(vlan::VlanTagHdr))
    {
        codec_events::decoder_event(p, DECODE_BAD_VLAN);
        return false;
    }

    const vlan::VlanTagHdr *vh = reinterpret_cast<const vlan::VlanTagHdr *>(raw_pkt);
    const uint16_t proto = ntohs(vh->vth_proto);


    /* check to see if we've got an encapsulated LLC layer
     * http://www.geocities.com/billalexander/ethernet.html
     */
    if(proto <= ETHERNET_MAX_LEN_ENCAP)
        next_prot_id = ETHERNET_LLC;
    else
        next_prot_id = proto;


    // Vlan IDs 0 and 4095 are reserved.
    const uint16_t vid = vlan::vth_vlan(vh);
    if (vid == 0 || vid == 4095)
        codec_events::decoder_event(p, DECODE_BAD_VLAN);


    lyr_len = sizeof(vlan::VlanTagHdr);
    p->proto_bits |= PROTO_BIT__VLAN;
    return true;
}

void VlanCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
                    const Packet* const)
{
    const vlan::VlanTagHdr *vh = reinterpret_cast<const vlan::VlanTagHdr *>(raw_pkt);
    const uint16_t proto = ntohs(vh->vth_proto);
    const uint16_t vid = vlan::vth_vlan(vh);


    TextLog_Putc(text_log, '\t');
    TextLog_Print(text_log, "Priority:%d(0x%X) CFI:%d "
        "Vlan_ID:%d(0x%04X)",
        vlan::vth_priority(vh), vlan::vth_priority(vh),
        vlan::vth_cfi(vh), vid, vid);


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

static void dtor(Codec *cd)
{ delete cd; }

static const CodecApi vlan_api =
{
    {
        PT_CODEC,
        CD_VLAN_NAME,
        CDAPI_PLUGIN_V0,
        0,
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
{
    &vlan_api.base,
    nullptr
};
#else
const BaseApi* cd_vlan = &vlan_api.base;
#endif

