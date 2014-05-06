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
#include "codecs/decode_module.h"
#include "framework/codec.h"
#include "time/profiler.h"
#include "protocols/packet.h"
#include "protocols/eth.h"
#include "events/codec_events.h"

namespace
{

class EthCodec : public Codec
{
public:
    EthCodec() : Codec("eth"){};
    ~EthCodec(){};


    virtual void get_protocol_ids(std::vector<uint16_t>&) {};
    virtual void get_data_link_type(std::vector<int>&);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id);

    // DELETE
    #include "codecs/sf_protocols.h"
    virtual inline PROTO_ID get_proto_id() { return PROTO_ETH; };
    
};

} // anonymous


void EthCodec::get_data_link_type(std::vector<int>&v)
{
    v.push_back(DLT_EN10MB);
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
bool EthCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &lyr_len, uint16_t& next_prot_id)
{

//    dc.eth++;
//    dc.total_processed++;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)len, (unsigned long)p->pkth->pktlen);
            );

    /* do a little validation */
    if(len < eth::hdr_len())
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "WARNING: Truncated eth header (%d bytes).\n", len););

        codec_events::decoder_event(p, DECODE_ETH_HDR_TRUNC);

//        dc.discards++;
//        dc.ethdisc++;
        return false;
    }

    /* lay the ethernet structure over the packet data */
    p->eh = reinterpret_cast<const eth::EtherHdr *>(raw_pkt);

    DEBUG_WRAP(
            DebugMessage(DEBUG_DECODE, "%X:%X:%X:%X:%X:%X -> %X:%X:%X:%X:%X:%X\n",
                p->eh->ether_src[0],
                p->eh->ether_src[1], p->eh->ether_src[2], p->eh->ether_src[3],
                p->eh->ether_src[4], p->eh->ether_src[5], p->eh->ether_dst[0],
                p->eh->ether_dst[1], p->eh->ether_dst[2], p->eh->ether_dst[3],
                p->eh->ether_dst[4], p->eh->ether_dst[5]);
            );
    DEBUG_WRAP(
            DebugMessage(DEBUG_DECODE, "type:0x%X len:0x%X\n",
                ntohs(p->eh->ether_type), p->pkth->pktlen)
            );

    next_prot_id = ntohs(p->eh->ether_type);
    if (next_prot_id > eth::min_ethertype() )
    {
        lyr_len = eth::hdr_len();
        return true;
    }

//   add this alert type
//    if(len > MAX_LENGTH) {
//        CodecEvents::decoder_event(p, DECODE_ETH_INVALID_FRAME);


    return false;
}


#if 0

//-------------------------------------------------------------------------
// ethernet
//-------------------------------------------------------------------------

EncStatus Eth_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    // not raw ip -> encode layer 2
    int raw = ( enc->flags & ENC_FLAG_RAW );

    eth::EtherHdr* hi = (eth::EtherHdr*)enc->p->layers[enc->layer-1].start;
    PROTO_ID next = NextEncoder(enc);

    // if not raw ip AND out buf is empty
    if ( !raw && (out->off == out->end) )
    {
        // for alignment
        out->off = out->end = SPARC_TWIDDLE;
    }
    // if not raw ip OR out buf is not empty
    if ( !raw || (out->off != out->end) )
    {
        // we get here for outer-most layer when not raw ip
        // we also get here for any encapsulated ethernet layer.
        eth::EtherHdr* ho = (eth::EtherHdr*)(out->base + out->end);
        UPDATE_BOUND(out, sizeof(*ho));
        uint8_t *dst_mac = Encode_GetDstMAC();

        ho->ether_type = hi->ether_type;
        if ( FORWARD(enc) )
        {
            memcpy(ho->ether_src, hi->ether_src, sizeof(ho->ether_src));
            /*If user configured remote MAC address, use it*/
            if (NULL != dst_mac)
                memcpy(ho->ether_dst, dst_mac, sizeof(ho->ether_dst));
            else
                memcpy(ho->ether_dst, hi->ether_dst, sizeof(ho->ether_dst));
        }
        else
        {
            memcpy(ho->ether_src, hi->ether_dst, sizeof(ho->ether_src));
            /*If user configured remote MAC address, use it*/
            if (NULL != dst_mac)
                memcpy(ho->ether_dst, dst_mac, sizeof(ho->ether_dst));
            else
                memcpy(ho->ether_dst, hi->ether_src, sizeof(ho->ether_dst));
        }
    }
    if ( next < PROTO_MAX )
        return encoders[next].fencode(enc, in, out);

    return EncStatus::ENC_OK;
}

EncStatus Eth_Update (Packet*, Layer* lyr, uint32_t* len)
{
    *len += lyr->length;
    return EncStatus::ENC_OK;
}

void Eth_Format (EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    eth::EtherHdr* ch = (eth::EtherHdr*)lyr->start;
    c->eh = ch;

    if ( REVERSE(f) )
    {
        int i = lyr - c->layers;
        eth::EtherHdr* ph = (eth::EtherHdr*)p->layers[i].start;

        memcpy(ch->ether_dst, ph->ether_src, sizeof(ch->ether_dst));
        memcpy(ch->ether_src, ph->ether_dst, sizeof(ch->ether_src));
    }
}

#endif

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor()
{
    return new EthCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const char* name = "eth";
static const CodecApi eth_api =
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

const BaseApi* cd_eth = &eth_api.base;
