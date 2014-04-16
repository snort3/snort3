/* $Id: decode.c,v 1.285 2013-06-29 03:03:00 rcombs Exp $ */

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

#include "generators.h"
#include "framework/codec.h"
#include "time/profiler.h"
#include "protocols/packet.h"
#include "codecs/codec_events.h"




#include <pcap.h>



namespace
{

class EthCodec : public Codec
{
public:
    EthCodec() : Codec("Eth"){};
    ~EthCodec();


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &p_hdr_len, int &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual void get_data_link_type(std::vector<int>&);
    
};

} // anonymous namespace



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
        Packet *p, uint16_t &p_hdr_len, int &next_prot_id)
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

        if ( Event_Enabled(DECODE_ETH_HDR_TRUNC) )
            DecoderEvent(p, EVARGS(ETH_HDR_TRUNC));

//        dc.discards++;
//        dc.ethdisc++;
        return false;
    }

    /* lay the ethernet structure over the packet data */
    p->eh = reinterpret_cast<const eth::EtherHdr *>(raw_pkt);
//    PushLayer(PROTO_ETH, p, pkt, sizeof(*p->eh));

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
    p_hdr_len = eth::hdr_len();

#if 0
    /* grab out the network type */
    switch(ntohs(p->eh->ether_type))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(
                    DebugMessage(DEBUG_DECODE,
                        "IP datagram size calculated to be %lu bytes\n",
                        (unsigned long)(cap_len - ETHERNET_HEADER_LEN));
                    );

            DecodeIP(p->pkt + ETHERNET_HEADER_LEN,
                    cap_len - ETHERNET_HEADER_LEN, p);

            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DecodeARP(p->pkt + ETHERNET_HEADER_LEN,
                    cap_len - ETHERNET_HEADER_LEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(p->pkt + ETHERNET_HEADER_LEN,
                    (cap_len - ETHERNET_HEADER_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_PPPoE_DISC:
        case ETHERNET_TYPE_PPPoE_SESS:
            DecodePPPoEPkt(p->pkt + ETHERNET_HEADER_LEN,
                    (cap_len - ETHERNET_HEADER_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

#ifndef NO_NON_ETHER_DECODER
        case ETHERNET_TYPE_IPX:
            DecodeIPX(p->pkt + ETHERNET_HEADER_LEN,
                    (cap_len - ETHERNET_HEADER_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;
#endif

        case ETHERNET_TYPE_LOOP:
            DecodeEthLoopback(p->pkt + ETHERNET_HEADER_LEN,
                    (cap_len - ETHERNET_HEADER_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + ETHERNET_HEADER_LEN,
                    cap_len - ETHERNET_HEADER_LEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_MPLS_MULTICAST:
            if(!ScMplsMulticast())
            {
                //additional check for DecoderAlerts will be done now.
            	DecoderEvent(p, DECODE_BAD_MPLS, DECODE_MULTICAST_MPLS_STR);
            }
        case ETHERNET_TYPE_MPLS_UNICAST:
                DecodeMPLS(p->pkt + ETHERNET_HEADER_LEN,
                    cap_len - ETHERNET_HEADER_LEN, p);
                PREPROC_PROFILE_END(decodePerfStats);
                return;

        default:
            // TBD add decoder drop event for unknown eth type
            dc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }
#endif 

    return true;
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


void EthCodec::get_data_link_type(std::vector<int>&v)
{
    v.push_back(DLT_EN10MB);
}

void EthCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ipv6::ethertype());
    v.push_back(IPPROTO_IPV6);
}

static Codec* ctor()
{
    return new EthCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const char* name = "eth_codec";

static const CodecApi ipv6_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
};

