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



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pcap.h>
#include "protocols/wlan.h"
#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"
#include "protocols/protocol_ids.h"
#include "main/snort.h"


#ifdef DEBUG_MSGS
#include "log/log.h"
#endif

namespace
{

#define CD_WLAN_NAME "wlan"
static const RuleMap wlan_rules[] =
{
    { DECODE_BAD_80211_ETHLLC, "(" CD_WLAN_NAME ") Bad 802.11 LLC header" },
    { DECODE_BAD_80211_OTHER, "(" CD_WLAN_NAME ") Bad 802.11 Extra LLC Info" },
    { 0, nullptr }
};

class WlanCodecModule : public DecodeModule
{
public:
    WlanCodecModule() : DecodeModule(CD_WLAN_NAME) {}

    const RuleMap* get_rules() const
    { return wlan_rules; }
};


class WlanCodec : public Codec
{
public:
    WlanCodec() : Codec(CD_WLAN_NAME){};
    ~WlanCodec() {};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    virtual void get_data_link_type(std::vector<int>&);

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

#define MINIMAL_IEEE80211_HEADER_LEN    10    /* Ack frames and others */
#define IEEE802_11_DATA_HDR_LEN         24    /* Header for data packets */

} // namespace


void WlanCodec::get_data_link_type(std::vector<int>&v)
{
#ifdef DLT_IEEE802_11
    v.push_back(DLT_IEEE802_11);
#endif
}

bool WlanCodec::decode(const uint8_t *raw_pkt, const uint32_t &raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    uint32_t cap_len = raw_len;
    // reinterpret the raw data into this codec's data format


    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)cap_len, (unsigned long)raw_len););

    /* do a little validation */
    if(cap_len < MINIMAL_IEEE80211_HEADER_LEN)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < IEEE 802.11 header length! "
                         "(%d bytes)\n", cap_len);
        }

        return false;
    }

    /* lay the wireless structure over the packet data */
    const wlan::WifiHdr *wifih = reinterpret_cast<const wlan::WifiHdr *>(raw_pkt);

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "%X   %X\n", *wifih->addr1,
                *wifih->addr2););

    /* determine frame type */
    switch(wifih->frame_control & 0x00ff)
    {
        /* management frames */
        case WLAN_TYPE_MGMT_ASREQ:
        case WLAN_TYPE_MGMT_ASRES:
        case WLAN_TYPE_MGMT_REREQ:
        case WLAN_TYPE_MGMT_RERES:
        case WLAN_TYPE_MGMT_PRREQ:
        case WLAN_TYPE_MGMT_PRRES:
        case WLAN_TYPE_MGMT_BEACON:
        case WLAN_TYPE_MGMT_ATIM:
        case WLAN_TYPE_MGMT_DIS:
        case WLAN_TYPE_MGMT_AUTH:
        case WLAN_TYPE_MGMT_DEAUTH:
            break;

            /* Control frames */
        case WLAN_TYPE_CONT_PS:
        case WLAN_TYPE_CONT_RTS:
        case WLAN_TYPE_CONT_CTS:
        case WLAN_TYPE_CONT_ACK:
        case WLAN_TYPE_CONT_CFE:
        case WLAN_TYPE_CONT_CFACK:
            break;
            /* Data packets without data */
        case WLAN_TYPE_DATA_NULL:
        case WLAN_TYPE_DATA_CFACK:
        case WLAN_TYPE_DATA_CFPL:
        case WLAN_TYPE_DATA_ACKPL:

            break;
        case WLAN_TYPE_DATA_DTCFACK:
        case WLAN_TYPE_DATA_DTCFPL:
        case WLAN_TYPE_DATA_DTACKPL:
        case WLAN_TYPE_DATA_DATA:
        {

            if(cap_len < IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc))
            {
                codec_events::decoder_event(p, DECODE_BAD_80211_ETHLLC);
                return false;
            }

            const EthLlc *ehllc = reinterpret_cast<const EthLlc*>(raw_pkt + IEEE802_11_DATA_HDR_LEN);

#ifdef DEBUG_MSGS
            LogNetData((uint8_t*) ehllc, sizeof(EthLlc), NULL);

            printf("LLC Header:\n");
            printf("   DSAP: 0x%X\n", ehllc->dsap);
            printf("   SSAP: 0x%X\n", ehllc->ssap);
#endif

            if(ehllc->dsap == ETH_DSAP_IP && ehllc->ssap == ETH_SSAP_IP)
            {
                if(cap_len < IEEE802_11_DATA_HDR_LEN +
                   sizeof(EthLlc) + sizeof(EthLlcOther))
                {
                    codec_events::decoder_event(p, DECODE_BAD_80211_OTHER);
                    return false;
                }

                const EthLlcOther *ehllcother = reinterpret_cast<const EthLlcOther *>(raw_pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc));
#ifdef DEBUG_MSGS
                LogNetData((uint8_t*)ehllcother, sizeof(EthLlcOther), NULL);

                printf("LLC Other Header:\n");
                printf("   CTRL: 0x%X\n", ehllcother->ctrl);
                printf("   ORG: 0x%02X%02X%02X\n", ehllcother->org_code[0],
                        ehllcother->org_code[1], ehllcother->org_code[2]);
                printf("   PROTO: 0x%04X\n", ntohs(ehllcother->proto_id));
#endif
                next_prot_id = ntohs(ehllcother->proto_id);

                switch(ntohs(ehllcother->proto_id))
                {
                    case ETHERTYPE_IPV4:
                    case ETHERTYPE_ARP:
                    case ETHERTYPE_REVARP:
                    case ETHERTYPE_EAPOL:
                        lyr_len = IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc) + sizeof(EthLlcOther);


                    case ETHERTYPE_8021Q:
                    case ETHERTYPE_IPV6:
                        lyr_len = IEEE802_11_DATA_HDR_LEN;
                    default:
                        return false;
                }
            }
            break;
        }
        default:
            break;
    }

    return true;
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new WlanCodecModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Codec* ctor(Module*)
{
    return new WlanCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const CodecApi wlan_api =
{
    {
        PT_CODEC,
        CD_WLAN_NAME,
        CDAPI_PLUGIN_V0,
        0,
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
{
    &wlan_api.base,
    nullptr
};
#else
const BaseApi* cd_wlan = &wlan_api.base;
#endif
