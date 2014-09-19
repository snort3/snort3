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
// cd_eth.cc author Josh Rosenbaum <jrosenba@cisco.com>


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pcap.h>
#include "codecs/decode_module.h"
#include "framework/codec.h"
#include "protocols/packet.h"
#include "protocols/eth.h"
#include "codecs/codec_events.h"
#include "protocols/packet_manager.h"
#include "log/text_log.h"

#define CD_ETH_NAME "eth"
#define CD_ETH_HELP_STR "support for ethernet protocol"
#define CD_ETH_HELP ADD_DLT(ADD_DLT(CD_ETH_HELP_STR, DLT_EN10MB), DLT_PPP_ETHER)

namespace
{

static const RuleMap eth_rules[] =
{
    { DECODE_ETH_HDR_TRUNC, "(" CD_ETH_NAME ") truncated eth header" },
    { 0, nullptr }
};

class EthModule : public DecodeModule
{
public:
    EthModule() : DecodeModule(CD_ETH_NAME, CD_ETH_HELP) {}

    const RuleMap* get_rules() const
    { return eth_rules; }
};


class EthCodec : public Codec
{
public:
    EthCodec() : Codec(CD_ETH_NAME){};
    ~EthCodec(){};

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual void get_data_link_type(std::vector<int>&);
    virtual void log(TextLog* const, const uint8_t* /*raw_pkt*/,
        const Packet*const );
    virtual bool decode(const RawData&, CodecData&, SnortData&);
    virtual bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
                        EncState&, Buffer&);
    virtual bool update(Packet*, Layer*, uint32_t* len);
    virtual void format(EncodeFlags, const Packet* p, Packet* c, Layer*);
};

} // namespace

#ifndef DLT_PPP_ETHER
// For PPP over Eth, the first layer is ethernet.
constexpr int DLT_PPP_ETHER = 51;
#endif

void EthCodec::get_data_link_type(std::vector<int>&v)
{
    v.push_back(DLT_PPP_ETHER);
    v.push_back(DLT_EN10MB);
}

void EthCodec::get_protocol_ids(std::vector<uint16_t>&v)
{
    v.push_back(ETHERNET_802_3);
}


//--------------------------------------------------------------------
// decode.c::Ethernet
//--------------------------------------------------------------------

/*
 * Function: DecodeEthPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
bool EthCodec::decode(const RawData& raw, CodecData& codec, SnortData&)
{

    /* do a little validation */
    if(raw.len < eth::ETH_HEADER_LEN)
    {
        codec_events::decoder_event(codec, DECODE_ETH_HDR_TRUNC);
        return false;
    }

    /* lay the ethernet structure over the packet data */
    const eth::EtherHdr *eh = reinterpret_cast<const eth::EtherHdr *>(raw.data);


    uint16_t next_prot = ntohs(eh->ether_type);
    if (next_prot > eth::MIN_ETHERTYPE )
        codec.proto_bits |= PROTO_BIT__ETH;
    else
        next_prot = ETHERNET_LLC;

    codec.next_prot_id = next_prot;
    codec.lyr_len = eth::ETH_HEADER_LEN;
    return true;
}


void EthCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
                    const Packet* const)
{
    const eth::EtherHdr *eh = reinterpret_cast<const eth::EtherHdr *>(raw_pkt);

    /* src addr */
    TextLog_Print(text_log, "%02X:%02X:%02X:%02X:%02X:%02X -> ", eh->ether_src[0],
        eh->ether_src[1], eh->ether_src[2], eh->ether_src[3],
        eh->ether_src[4], eh->ether_src[5]);

    /* dest addr */
    TextLog_Print(text_log, "%02X:%02X:%02X:%02X:%02X:%02X", eh->ether_dst[0],
        eh->ether_dst[1], eh->ether_dst[2], eh->ether_dst[3],
        eh->ether_dst[4], eh->ether_dst[5]);

    const uint16_t prot = ntohs(eh->ether_type);

    if (prot <= eth::MIN_ETHERTYPE)
        TextLog_Print(text_log, "  len:0x%04X", prot);
    else
        TextLog_Print(text_log, "  type:0x%04X", prot);
}

//-------------------------------------------------------------------------
// ethernet
//-------------------------------------------------------------------------

bool EthCodec::encode(const uint8_t* const raw_in, const uint16_t /*raw_len*/,
                      EncState& enc, Buffer& buf)
{
    // not raw ip -> encode layer 2
    int raw = ( enc.flags & ENC_FLAG_RAW );
    const eth::EtherHdr* hi = reinterpret_cast<const eth::EtherHdr*>(raw_in);
    eth::EtherHdr* ho;

    // if not raw ip AND out buf is empty
    if ( !raw && (buf.size() == 0) )
    {
        // for alignment
        if (!buf.allocate(SPARC_TWIDDLE))
            return false;

        buf.off = SPARC_TWIDDLE;
    }

    // if not raw ip OR out buf is not empty
    if ( !raw || (buf.size() != 0) )
    {
        // we get here for outer-most layer when not raw ip
        // we also get here for any encapsulated ethernet layer.
        if (!buf.allocate(sizeof(*ho)))
            return false;

        ho = reinterpret_cast<eth::EtherHdr*>(buf.base);

        if (enc.ethertype_set())
            ho->ether_type = enc.next_ethertype;
        else
            ho->ether_type = hi->ether_type;

        uint8_t *dst_mac = PacketManager::encode_get_dst_mac();
        
        if ( forward(enc.flags) )
        {
            memcpy(ho->ether_src, hi->ether_src, sizeof(ho->ether_src));
            /*If user configured remote MAC address, use it*/
            if (nullptr != dst_mac)
                memcpy(ho->ether_dst, dst_mac, sizeof(ho->ether_dst));
            else
                memcpy(ho->ether_dst, hi->ether_dst, sizeof(ho->ether_dst));
        }
        else
        {
            memcpy(ho->ether_src, hi->ether_dst, sizeof(ho->ether_src));
            /*If user configured remote MAC address, use it*/
            if (nullptr != dst_mac)
                memcpy(ho->ether_dst, dst_mac, sizeof(ho->ether_dst));
            else
                memcpy(ho->ether_dst, hi->ether_src, sizeof(ho->ether_dst));
        }
    }

    enc.next_ethertype = 0;
    enc.next_proto = ENC_PROTO_UNSET;
    return true;
}

bool EthCodec::update (Packet*, Layer* lyr, uint32_t* len)
{
    *len += lyr->length;
    return true;
}

void EthCodec::format(EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    eth::EtherHdr* ch = (eth::EtherHdr*)lyr->start;

    if ( reverse(f) )
    {
        int i = lyr - c->layers;
        eth::EtherHdr* ph = (eth::EtherHdr*)p->layers[i].start;

        memcpy(ch->ether_dst, ph->ether_src, sizeof(ch->ether_dst));
        memcpy(ch->ether_src, ph->ether_dst, sizeof(ch->ether_src));
    }
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new EthModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new EthCodec(); }

static void dtor(Codec *cd)
{ delete cd; }

static const CodecApi eth_api =
{
    { 
        PT_CODEC,
        CD_ETH_NAME,
        CD_ETH_HELP,
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
    &eth_api.base,
    nullptr
};
#else
const BaseApi* cd_eth = &eth_api.base;
#endif
