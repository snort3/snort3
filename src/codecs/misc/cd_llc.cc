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
// cd_llc.cc author Josh Rosenbaum <jrosenba@cisco.com>


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "protocols/packet.h"
#include "framework/module.h"
#include "codecs/codec_events.h"
#include "codecs/decode_module.h"
#include "log/text_log.h"
#include "protocols/packet_manager.h"

// yes, macros are necessary. The API and class constructor require different strings.
//
// this macros is defined in the module to ensure identical names. However,
// if you don't want a module, define the name here.
#define LLC_NAME "llc"
#define LLC_HELP "support for logical link control"

namespace
{

class LlcCodec : public Codec
{
public:
    LlcCodec() : Codec(LLC_NAME){};
    ~LlcCodec() {};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t &raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    virtual void log(TextLog* const, const uint8_t* /*raw_pkt*/,
        const Packet* const);
    virtual void get_protocol_ids(std::vector<uint16_t>&);
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
    uint16_t proto_id;
};

#define ETH_DSAP_SNA                  0x08    /* SNA */
#define ETH_SSAP_SNA                  0x00    /* SNA */
#define ETH_DSAP_STP                  0x42    /* Spanning Tree Protocol */
#define ETH_SSAP_STP                  0x42    /* Spanning Tree Protocol */
#define ETH_DSAP_IP                   0xaa    /* IP */
#define ETH_SSAP_IP                   0xaa    /* IP */

#define ETH_ORG_CODE_ETHR              0x000000    /* Encapsulated Ethernet */
#define ETH_ORG_CODE_CDP               0x00000c    /* Cisco Discovery Proto */

} // namespace


void LlcCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERNET_LLC);
}

bool LlcCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet* p, uint16_t& lyr_len, uint16_t& next_prot_id)
{
    if(raw_len < sizeof(EthLlc))
    {
        // FIXIT-L - J - Need a better alert
        codec_events::decoder_event(p, DECODE_BAD_VLAN_ETHLLC);
        return false;
    }

     const EthLlc *ehllc = reinterpret_cast<const EthLlc *>(raw_pkt);



    if(ehllc->dsap == ETH_DSAP_IP &&
        ehllc->ssap == ETH_SSAP_IP)
    {
        if (raw_len <  sizeof(EthLlc) + sizeof(EthLlcOther))
        {
            codec_events::decoder_event(p, DECODE_BAD_VLAN_ETHLLC);
            return false;
        }

        const EthLlcOther *ehllcother = reinterpret_cast<const EthLlcOther *>(raw_pkt + sizeof(EthLlc));

        if (ehllcother->org_code[0] == 0 &&
            ehllcother->org_code[1] == 0 &&
            ehllcother->org_code[2] == 0)
        {
            lyr_len = sizeof(EthLlc) + sizeof(EthLlcOther);
            next_prot_id = ntohs(ehllcother->proto_id);
        }
    }

    return true;
}

void LlcCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
                    const Packet* const)
{
    const EthLlc *ehllc = reinterpret_cast<const EthLlc *>(raw_pkt);

    TextLog_Print(text_log, "DSAP:0x%X SSAP:0x%X CTRL:0x%X",
        ehllc->dsap, ehllc->ssap, ehllc->ctrl);

    // Assuming that if these three conditions are met, this is SNAP.
    if(ehllc->dsap == ETH_DSAP_IP &&
        ehllc->ssap == ETH_SSAP_IP)
    {

        const EthLlcOther *other = reinterpret_cast<const EthLlcOther *>(raw_pkt + sizeof(EthLlc));
        const uint16_t proto = ntohs(other->proto_id);

        TextLog_Print(text_log, " ORG:0x%02X%02X%02X PROTO:0x%04X",
            other->org_code[0], other->org_code[1], other->org_code[2],
            proto);
    }
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new LlcCodec(); }

static void dtor(Codec *cd)
{ delete cd; }


static const CodecApi llc_api =
{
    {
        PT_CODEC,
        LLC_NAME,
        LLC_HELP,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
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
{
    &llc_api.base,
    nullptr
};
#else
const BaseApi* cd_llc = &llc_api.base;
#endif
