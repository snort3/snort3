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
// cd_vlan.cc author Josh Rosenbaum <jorosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "protocols/packet.h"
#include "codecs/decode_module.h"
#include "events/codec_events.h"
#include "codecs/decode.h"

namespace
{

class VlanCodec : public Codec
{
public:
    VlanCodec() : Codec("vlan"){};
    ~VlanCodec(){};

    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, int &next_prot_id);

    
    // DELETE from here and below
    #include "codecs/sf_protocols.h"
    virtual inline PROTO_ID get_proto_id() { return PROTO_VLAN; };
};

} // namespace

static const uint16_t ETHERNET_TYPE_8021Q = 0x8100;


static inline uint32_t len_vlan_llc_other()
{
    return (sizeof(VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther));
}


void VlanCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERNET_TYPE_8021Q);
}


bool VlanCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &lyr_len, int &next_prot_id)
{
//    dc.vlan++;

//    if (p->greh != NULL)
//        dc.gre_vlan++;

    if(len < sizeof(VlanTagHdr))
    {
        codec_events::decoder_event(p, DECODE_BAD_VLAN);

        // TBD add decoder drop event for VLAN hdr len issue
//        dc.discards++;
        p->iph = NULL;
        p->family = NO_IP;
        return false;
    }

    p->vh = (VlanTagHdr *) raw_pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Vlan traffic:\n");
               DebugMessage(DEBUG_DECODE, "   Priority: %d(0x%X)\n",
                            VTH_PRIORITY(p->vh), VTH_PRIORITY(p->vh));
               DebugMessage(DEBUG_DECODE, "   CFI: %d\n", VTH_CFI(p->vh));
               DebugMessage(DEBUG_DECODE, "   Vlan ID: %d(0x%04X)\n",
                            VTH_VLAN(p->vh), VTH_VLAN(p->vh));
               DebugMessage(DEBUG_DECODE, "   Vlan Proto: 0x%04X\n",
                            ntohs(p->vh->vth_proto));
               );

    /* check to see if we've got an encapsulated LLC layer
     * http://www.geocities.com/billalexander/ethernet.html
     */
    if(ntohs(p->vh->vth_proto) <= ETHERNET_MAX_LEN_ENCAP)
    {
        if(len < sizeof(VlanTagHdr) + sizeof(EthLlc))
        {
            codec_events::decoder_event(p, DECODE_BAD_VLAN_ETHLLC);

//            dc.discards++;
            p->iph = NULL;
            p->family = NO_IP;
            return false;
        }

        p->ehllc = (EthLlc *) (raw_pkt + sizeof(VlanTagHdr));

        DEBUG_WRAP(
                DebugMessage(DEBUG_DECODE, "LLC Header:\n");
                DebugMessage(DEBUG_DECODE, "   DSAP: 0x%X\n", p->ehllc->dsap);
                DebugMessage(DEBUG_DECODE, "   SSAP: 0x%X\n", p->ehllc->ssap);
                );

        if(p->ehllc->dsap == ETH_DSAP_IP && p->ehllc->ssap == ETH_SSAP_IP)
        {
            if ( len < len_vlan_llc_other() )
            {
                codec_events::decoder_event(p, DECODE_BAD_VLAN_OTHER);

//                dc.discards++;
                p->iph = NULL;
                p->family = NO_IP;

                return false;
            }

            p->ehllcother = (EthLlcOther *) (raw_pkt + sizeof(VlanTagHdr) + sizeof(EthLlc));

            DEBUG_WRAP(
                    DebugMessage(DEBUG_DECODE, "LLC Other Header:\n");
                    DebugMessage(DEBUG_DECODE, "   CTRL: 0x%X\n",
                        p->ehllcother->ctrl);
                    DebugMessage(DEBUG_DECODE, "   ORG: 0x%02X%02X%02X\n",
                        p->ehllcother->org_code[0], p->ehllcother->org_code[1],
                        p->ehllcother->org_code[2]);
                    DebugMessage(DEBUG_DECODE, "   PROTO: 0x%04X\n",
                        ntohs(p->ehllcother->proto_id));
                    );

//            PushLayer(PROTO_VLAN, p, pkt, sizeof(*p->vh));

            lyr_len = len_vlan_llc_other();
            next_prot_id = ntohs(p->ehllcother->proto_id);
        }
    }
    else
    {
        lyr_len = sizeof(VlanTagHdr);
        next_prot_id = ntohs(p->vh->vth_proto);

    }

    return true;
}

#if 0

/*
 * ENCODER
 */
void VLAN_Format (EncodeFlags, const Packet*, Packet* c, Layer* lyr)
{
    c->vh = (VlanTagHdr*)lyr->start;
}
#endif

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor()
{
    return new VlanCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const char* name = "vlan";
static const CodecApi vlan_api =
{
    {
        PT_CODEC,
        name,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr,
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

