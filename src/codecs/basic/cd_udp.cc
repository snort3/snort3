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

#include <string.h>
#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

#include "codecs/decode_module.h"
#include "protocols/udp.h"
#include "protocols/teredo.h"
#include "protocols/undefined_protocols.h"

#include "framework/codec.h"
#include "codecs/codec_events.h"
#include "packet_io/active.h"


namespace
{

class UdpCodec : public Codec
{
public:
    UdpCodec() : Codec("Udp"){};
    ~UdpCodec(){};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, int &next_prot_id);

    // DELETE
    #include "codecs/sf_protocols.h"
    virtual inline PROTO_ID get_proto_id() { return PROTO_UDP; };

    
};

} // anonymous namespace





static inline void PopUdp (Packet* p);
static inline void UDPMiscTests(Packet *p);
static inline unsigned short in_chksum_udp6(pseudoheader6 *, unsigned short *, int);
static inline unsigned short in_chksum_udp(pseudoheader *, unsigned short *, int);




bool UdpCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
    Packet *p, uint16_t &lyr_len, int &next_prot_id)
{
    uint16_t uhlen;
    u_char fragmented_udp_flag = 0;

    if (p->proto_bits & (PROTO_BIT__TEREDO | PROTO_BIT__GTP))
        p->outer_udph = p->udph;

    if(len < sizeof(udp::UDPHdr))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                "Truncated UDP header (%d bytes)\n", len););

        codec_events::decoder_event(p, DECODE_UDP_DGRAM_LT_UDPHDR);

        PopUdp(p);
        return false;
    }

    /* set the ptr to the start of the UDP header */
    p->inner_udph = p->udph = reinterpret_cast<udp::UDPHdr*>(const_cast<uint8_t*>(raw_pkt));

    if (!p->frag_flag)
    {
        uhlen = ntohs(p->udph->uh_len);
    }
    else
    {
        if(IS_IP6(p))
        {
            uint16_t ip_len = ntohs(GET_IPH_LEN(p));
            /* subtract the distance from udp header to 1st ip6 extension */
            /* This gives the length of the UDP "payload", when fragmented */
            uhlen = ip_len - ((u_char *)p->udph - (u_char *)p->ip6_extensions[0].data);
        }
        else
        {
            uint16_t ip_len = ntohs(GET_IPH_LEN(p));
            /* Don't forget, IP_HLEN is a word - multiply x 4 */
            uhlen = ip_len - (GET_IPH_HLEN(p) * 4 );
        }
        fragmented_udp_flag = 1;
    }

    /* verify that the header len is a valid value */
    if(uhlen < UDP_HEADER_LEN)
    {
        codec_events::decoder_event(p, DECODE_UDP_DGRAM_INVALID_LENGTH);

        PopUdp(p);
        return false;
    }

    /* make sure there are enough bytes as designated by length field */
    if(uhlen > len)
    {
        codec_events::decoder_event(p, DECODE_UDP_DGRAM_SHORT_PACKET);

        PopUdp(p);
        return false;
    }
    else if(uhlen < len)
    {
        codec_events::decoder_event(p, DECODE_UDP_DGRAM_LONG_PACKET);

        PopUdp(p);
        return false;
    }

    if (ScUdpChecksums())
    {
        /* look at the UDP checksum to make sure we've got a good packet */
        uint16_t csum;
        if(IS_IP4(p))
        {
            pseudoheader ph;
            ph.sip = *p->ip4h->ip_src.ip32;
            ph.dip = *p->ip4h->ip_dst.ip32;
            ph.zero = 0;
            ph.protocol = GET_IPH_PROTO(p);
            ph.len = p->udph->uh_len;
            /* Don't do checksum calculation if
             * 1) Fragmented, OR
             * 2) UDP header chksum value is 0.
             */
            if( !fragmented_udp_flag && p->udph->uh_chk )
            {
                csum = in_chksum_udp(&ph,
                    (uint16_t *)(p->udph), uhlen);
            }
            else
            {
                csum = 0;
            }
        }
        else
        {
            pseudoheader6 ph6;
            COPY4(ph6.sip, p->ip6h->ip_src.ip32);
            COPY4(ph6.dip, p->ip6h->ip_dst.ip32);
            ph6.zero = 0;
            ph6.protocol = GET_IPH_PROTO(p);
            ph6.len = htons((u_short)len);

            /* Alert on checksum value 0 for ipv6 packets */
            if(!p->udph->uh_chk)
            {
                csum = 1;
                codec_events::decoder_event(p, DECODE_UDP_IPV6_ZERO_CHECKSUM);
            }
            /* Don't do checksum calculation if
             * 1) Fragmented
             * (UDP checksum is not optional in IP6)
             */
            else if( !fragmented_udp_flag )
            {
                csum = in_chksum_udp6(&ph6,
                    (uint16_t *)(p->udph), uhlen);
            }
            else
            {
                csum = 0;
            }
        }
        if(csum)
        {
            /* Don't drop the packet if this was ESP or Teredo.
               Just stop decoding. */
            if (p->packet_flags & PKT_UNSURE_ENCAP)
            {
                PopUdp(p);
                return false;
            }

            p->error_flags |= PKT_ERR_CKSUM_UDP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad UDP Checksum\n"););
            codec_events::exec_udp_chksm_drop(p);
//            dc.invalid_checksums++;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "UDP Checksum: OK\n"););
        }
    }

    /* fill in the printout data structs */
    p->sp = ntohs(p->udph->uh_sport);
    p->dp = ntohs(p->udph->uh_dport);

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "UDP header starts at: %p\n", p->udph););

    lyr_len = udp::header_len();
    next_prot_id = -1;
//    PushLayer(PROTO_UDP, p, raw_pkt, udp::header_len());


    // set in packet manager
//    p->data = (uint8_t *) (raw_pkt + udp::header_len());
//    p->dsize = uhlen - udp::header_len(); // length validated above
    p->proto_bits |= PROTO_BIT__UDP;

    /*  Drop packet if we ignore this port  */
    if (ScIgnoreUdpPort(p->sp) || ScIgnoreUdpPort(p->dp))
    {
        /*  Ignore all preprocessors for this packet */
        p->packet_flags |= PKT_IGNORE;
        return true;
    }

    UDPMiscTests(p);

    if (teredo::is_teredo_port(p->sp) ||
        teredo::is_teredo_port(p->dp) ||
        ScDeepTeredoInspection())
    {
        if ( !p->frag_flag )
            next_prot_id = PROTOCOL_TEREDO;
    }

    if (ScGTPDecoding() &&
         (ScIsGTPPort(p->sp)||ScIsGTPPort(p->dp)))
    {
        if ( !p->frag_flag )
            next_prot_id = PROTOCOL_GTP;
    }
    
    return true;
}


/* UDP-layer decoder alerts */
static inline void UDPMiscTests(Packet *p)
{
    if (p->dsize > 4000)
        codec_events::decoder_event(p, DECODE_UDP_LARGE_PACKET);

    if (p->sp == 0 || p->dp == 0)
        codec_events::decoder_event(p, DECODE_UDP_PORT_ZERO);
}

/*
 * Function: DecodeUDP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the UDP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
static inline void PopUdp (Packet* p)
{
    p->udph = p->outer_udph;
    p->outer_udph = NULL;
//    dc.discards++;
//    dc.udisc++;

    // required for detect.c to short-circuit preprocessing
    if ( !p->dsize )
        p->dsize = p->ip_dsize;
}


/*
 * ENCODER
 */

#if 0

EncStatus UDP_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    PROTO_ID next = PROTO_MAX;

    if ( enc->layer < enc->p->next_layer )
    {
        next = enc->p->layers[enc->layer].proto;
    }
    if ((PROTO_GTP == next) && (encoders[next].fencode))
    {
        int len;
        EncStatus err;
        uint32_t start = out->end;

        udp::UDPHdr* hi = (udp::UDPHdr*)enc->p->layers[enc->layer-1].start;
        udp::UDPHdr* ho = (udp::UDPHdr*)(out->base + out->end);
        UPDATE_BOUND(out, sizeof(*ho));

        if ( FORWARD(enc) )
        {
            ho->uh_sport = hi->uh_sport;
            ho->uh_dport = hi->uh_dport;
        }
        else
        {
            ho->uh_sport = hi->uh_dport;
            ho->uh_dport = hi->uh_sport;
        }

        next = NextEncoder(enc);
        err = encoders[next].fencode(enc, in, out);
        if (EncStatus::ENC_OK != err ) return err;
        len = out->end - start;
        ho->uh_len = htons((uint16_t)len);

        ho->uh_chk = 0;

        if (IP_VER((IPHdr *)enc->ip_hdr) == 4) {
            pseudoheader ps;
            ps.sip = ((IPHdr *)enc->ip_hdr)->ip_src.s_addr;
            ps.dip = ((IPHdr *)enc->ip_hdr)->ip_dst.s_addr;
            ps.zero = 0;
            ps.protocol = IPPROTO_UDP;
            ps.len = ho->uh_len;
            ho->uh_chk = in_chksum_udp(&ps, (uint16_t *)ho, len);
        }
        else {
            pseudoheader6 ps6;
            memcpy(ps6.sip, ((ipv6::IP6RawHdr *)enc->ip_hdr)->ip6_src.s6_addr, sizeof(ps6.sip));
            memcpy(ps6.dip, ((ipv6::IP6RawHdr *)enc->ip_hdr)->ip6_dst.s6_addr, sizeof(ps6.dip));
            ps6.zero = 0;
            ps6.protocol = IPPROTO_UDP;
            ps6.len = ho->uh_len;
            ho->uh_chk = in_chksum_udp6(&ps6, (uint16_t *)ho, len);
        }

        return EncStatus::ENC_OK;
    }
    if ( IP_VER((IPHdr*)enc->ip_hdr) == 4 )
        return UN4_Encode(enc, in, out);

    return UN6_Encode(enc, in, out);
}

EncStatus UDP_Update (Packet* p, Layer* lyr, uint32_t* len)
{
    udp::UDPHdr* h = (udp::UDPHdr*)(lyr->start);

    *len += sizeof(*h) + p->dsize;
    h->uh_len = htons((uint16_t)*len);


    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) ) {
        h->uh_chk = 0;

        if (IS_IP4(p)) {
            pseudoheader ps;
            ps.sip = ((IPHdr *)(lyr-1)->start)->ip_src.s_addr;
            ps.dip = ((IPHdr *)(lyr-1)->start)->ip_dst.s_addr;
            ps.zero = 0;
            ps.protocol = IPPROTO_UDP;
            ps.len = htons((uint16_t)*len);
            h->uh_chk = in_chksum_udp(&ps, (uint16_t *)h, *len);
        } else {
            pseudoheader6 ps6;
            memcpy(ps6.sip, &p->ip6h->ip_src.ip32, sizeof(ps6.sip));
            memcpy(ps6.dip, &p->ip6h->ip_dst.ip32, sizeof(ps6.dip));
            ps6.zero = 0;
            ps6.protocol = IPPROTO_UDP;
            ps6.len = htons((uint16_t)*len);
            h->uh_chk = in_chksum_udp6(&ps6, (uint16_t *)h, *len);
        }
    }

    return EncStatus::ENC_OK;
}

void UDP_Format (EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    udp::UDPHdr* ch = (udp::UDPHdr*)lyr->start;
    c->udph = ch;

    if ( REVERSE(f) )
    {
        int i = lyr - c->layers;
        udp::UDPHdr* ph = (udp::UDPHdr*)p->layers[i].start;

        ch->uh_sport = ph->uh_dport;
        ch->uh_dport = ph->uh_sport;
    }
    c->sp = ntohs(ch->uh_sport);
    c->dp = ntohs(ch->uh_dport);
}

#endif

/*
 * CHECKSUMS
 */

/*
*  checksum udp
*
*  h    - pseudo header - 12 bytes
*  d    - udp hdr + payload
*  dlen - length of payload in bytes
*
*/
static inline unsigned short in_chksum_udp6(pseudoheader6 *ph,
    unsigned short * d, int dlen )
{
   uint16_t *h = (uint16_t *)ph;
   unsigned int cksum;
   unsigned short answer=0;

   /* PseudoHeader must have  12 bytes */
   cksum  = h[0];
   cksum += h[1];
   cksum += h[2];
   cksum += h[3];
   cksum += h[4];
   cksum += h[5];
   cksum += h[6];
   cksum += h[7];
   cksum += h[8];
   cksum += h[9];
   cksum += h[10];
   cksum += h[11];
   cksum += h[12];
   cksum += h[13];
   cksum += h[14];
   cksum += h[15];
   cksum += h[16];
   cksum += h[17];

   /* UDP must have 8 hdr bytes */
   cksum += d[0];
   cksum += d[1];
   cksum += d[2];
   cksum += d[3];

   dlen  -= 8; /* bytes   */
   d     += 4; /* short's */

   while(dlen >=32)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     cksum += d[4];
     cksum += d[5];
     cksum += d[6];
     cksum += d[7];
     cksum += d[8];
     cksum += d[9];
     cksum += d[10];
     cksum += d[11];
     cksum += d[12];
     cksum += d[13];
     cksum += d[14];
     cksum += d[15];
     d     += 16;
     dlen  -= 32;
   }

   while(dlen >=8)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     d     += 4;
     dlen  -= 8;
   }

   while(dlen > 1)
   {
     cksum += *d++;
     dlen  -= 2;
   }

   if( dlen == 1 )
   {
     *(unsigned char*)(&answer) = (*(unsigned char*)d);
     cksum += answer;
   }

   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);

   return (unsigned short)(~cksum);
}



static inline unsigned short in_chksum_udp(pseudoheader *ph,
     unsigned short * d, int dlen )
{
   uint16_t *h = (uint16_t *)ph;
   unsigned int cksum;
   unsigned short answer=0;

   /* PseudoHeader must have 36 bytes */
   cksum  = h[0];
   cksum += h[1];
   cksum += h[2];
   cksum += h[3];
   cksum += h[4];
   cksum += h[5];

   /* UDP must have 8 hdr bytes */
   cksum += d[0];
   cksum += d[1];
   cksum += d[2];
   cksum += d[3];

   dlen  -= 8; /* bytes   */
   d     += 4; /* short's */

   while(dlen >=32)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     cksum += d[4];
     cksum += d[5];
     cksum += d[6];
     cksum += d[7];
     cksum += d[8];
     cksum += d[9];
     cksum += d[10];
     cksum += d[11];
     cksum += d[12];
     cksum += d[13];
     cksum += d[14];
     cksum += d[15];
     d     += 16;
     dlen  -= 32;
   }

   while(dlen >=8)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     d     += 4;
     dlen  -= 8;
   }

   while(dlen > 1)
   {
     cksum += *d++;
     dlen  -= 2;
   }

   if( dlen == 1 )
   {
     *(unsigned char*)(&answer) = (*(unsigned char*)d);
     cksum += answer;
   }

   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);

   return (unsigned short)(~cksum);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static void get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_UDP);
}

static Codec* ctor()
{
    return new UdpCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const char* name = "udp_codec";

static const CodecApi udp_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0, nullptr, nullptr },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
    NULL,
    get_protocol_ids,
};


const BaseApi* cd_udp = &udp_api.base;

