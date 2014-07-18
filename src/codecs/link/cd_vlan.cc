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
#include "codecs/link/cd_vlan_module.h"
#include "codecs/codec_events.h"
#include "protocols/vlan.h"
#include "protocols/protocol_ids.h"
#include "codecs/sf_protocols.h"

namespace
{

class VlanCodec : public Codec
{
public:
    VlanCodec() : Codec(CD_VLAN_NAME){};
    ~VlanCodec(){};

    virtual PROTO_ID get_proto_id() { return PROTO_VLAN; };
    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
};

struct EthLlc
{
    uint8_t dsap;
    uint8_t ssap;
} ;


struct EthLlcOther
{
    uint8_t ctrl;
    uint8_t org_code[3];
    uint16_t proto_id;
};

} // namespace

static const unsigned int ETHERNET_MAX_LEN_ENCAP = 1518;    /* 802.3 (+LLC) or ether II ? */


static inline uint32_t len_vlan_llc_other()
{
    return (sizeof(vlan::VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther));
}


void VlanCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_8021Q);
}


bool VlanCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    if(len < sizeof(vlan::VlanTagHdr))
    {
        codec_events::decoder_event(p, DECODE_BAD_VLAN);

        // TBD add decoder drop event for VLAN hdr len issue
        p->iph = NULL;
        p->family = NO_IP;
        return false;
    }

    const vlan::VlanTagHdr *vh = reinterpret_cast<const vlan::VlanTagHdr *>(raw_pkt);

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Vlan traffic:\n");
               DebugMessage(DEBUG_DECODE, "   Priority: %d(0x%X)\n",
                            vlan::vth_priority(vh), vlan::vth_priority(vh));
               DebugMessage(DEBUG_DECODE, "   CFI: %d\n", vlan::vth_cfi(vh));
               DebugMessage(DEBUG_DECODE, "   Vlan ID: %d(0x%04X)\n",
                            vlan::vth_vlan(vh), vlan::vth_vlan(vh));
               DebugMessage(DEBUG_DECODE, "   Vlan Proto: 0x%04X\n",
                            ntohs(vh->vth_proto));
               );

    /* check to see if we've got an encapsulated LLC layer
     * http://www.geocities.com/billalexander/ethernet.html
     */
    if(ntohs(vh->vth_proto) <= ETHERNET_MAX_LEN_ENCAP)
    {
        if(len < sizeof(vlan::VlanTagHdr) + sizeof(EthLlc))
        {
            codec_events::decoder_event(p, DECODE_BAD_VLAN_ETHLLC);

            p->iph = NULL;
            p->family = NO_IP;
            return false;
        }

        const EthLlc *ehllc = reinterpret_cast<const EthLlc *>(raw_pkt + sizeof(vlan::VlanTagHdr));

        DEBUG_WRAP(
                DebugMessage(DEBUG_DECODE, "LLC Header:\n");
                DebugMessage(DEBUG_DECODE, "   DSAP: 0x%X\n", ehllc->dsap);
                DebugMessage(DEBUG_DECODE, "   SSAP: 0x%X\n", ehllc->ssap);
                );

        if(ehllc->dsap == ETH_DSAP_IP && ehllc->ssap == ETH_SSAP_IP)
        {
            if ( len < len_vlan_llc_other() )
            {
                codec_events::decoder_event(p, DECODE_BAD_VLAN_OTHER);

                p->iph = NULL;
                p->family = NO_IP;

                return false;
            }

            const EthLlcOther *ehllcother = reinterpret_cast<const EthLlcOther *>(raw_pkt + sizeof(vlan::VlanTagHdr) + sizeof(EthLlc));

            DEBUG_WRAP(
                    DebugMessage(DEBUG_DECODE, "LLC Other Header:\n");
                    DebugMessage(DEBUG_DECODE, "   CTRL: 0x%X\n",
                        ehllcother->ctrl);
                    DebugMessage(DEBUG_DECODE, "   ORG: 0x%02X%02X%02X\n",
                        ehllcother->org_code[0], ehllcother->org_code[1],
                        ehllcother->org_code[2]);
                    DebugMessage(DEBUG_DECODE, "   PROTO: 0x%04X\n",
                        ntohs(ehllcother->proto_id));
                    );

            lyr_len = len_vlan_llc_other();
            next_prot_id = ntohs(ehllcother->proto_id);
        }
    }
    else
    {
        lyr_len = sizeof(vlan::VlanTagHdr);
        next_prot_id = ntohs(vh->vth_proto);

    }

    p->proto_bits |= PROTO_BIT__VLAN;
    return true;
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new VlanModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Codec* ctor(Module*)
{
    return new VlanCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

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

