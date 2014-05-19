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


#include "snort.h"
#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"
#include "codecs/checksum.h"

#include "protocols/icmp6.h"
#include "protocols/icmp4.h"


namespace
{

class Icmp6Codec : public Codec
{
public:
    Icmp6Codec() : Codec("icmp6"){};
    ~Icmp6Codec(){};


    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
    virtual bool encode(EncState*, Buffer* out, const uint8_t* raw_in);
    virtual bool update(Packet*, Layer*, uint32_t* len);
    virtual void format(EncodeFlags, const Packet* p, Packet* c, Layer*);


    // DELETE from here and below
    #include "codecs/sf_protocols.h"
    virtual inline PROTO_ID get_proto_id() { return PROTO_ICMP6; };
    
};



} // anonymous namespace


void Icmp6Codec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ICMPV6);
}



static void DecodeICMPEmbeddedIP6(const uint8_t *pkt, const uint32_t len, Packet *p);

#if 0
static unsigned short in_chksum_icmp6(pseudoheader6 *, unsigned short *, int);
#endif


//--------------------------------------------------------------------
// decode.c::ICMP6
//--------------------------------------------------------------------

bool Icmp6Codec::decode(const uint8_t* raw_pkt, const uint32_t len, 
    Packet* p, uint16_t &lyr_len, uint16_t & /* next_prot_id */)
{
    if(len < icmp6::hdr_min_len())
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "WARNING: Truncated ICMP6 header (%d bytes).\n", len););

        codec_events::decoder_event(p, DECODE_ICMP6_HDR_TRUNC);
        return false;
    }

    p->icmp6h = reinterpret_cast<icmp6::ICMP6Hdr*>(const_cast<uint8_t*>(raw_pkt));
    p->icmph = reinterpret_cast<const ICMPHdr*>(raw_pkt); /* This is needed for icmp rules */


    /* Do checksums */
    if (ScIcmpChecksums())
    {
        uint16_t csum;

        if(IS_IP4(p))
        {
            csum = checksum::cksum_add((uint16_t *)(p->icmp6h), len);
        }
        /* IPv6 traffic */
        else
        {
            checksum::Pseudoheader6 ph6;
            COPY4(ph6.sip, p->ip6h->ip_src.ip32);
            COPY4(ph6.dip, p->ip6h->ip_dst.ip32);
            ph6.zero = 0;
            ph6.protocol = GET_IPH_PROTO(p);
            ph6.len = htons((u_short)len);

            csum = checksum::icmp_cksum((uint16_t *)(p->icmp6h), len, &ph6);
        }
        if(csum)
        {
            p->error_flags |= PKT_ERR_CKSUM_ICMP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad ICMP Checksum\n"););
            codec_events::exec_icmp_chksm_drop(p);
//            dc.invalid_checksums++;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"ICMP Checksum: OK\n"););
        }
    }

    p->dsize = (u_short)(len - icmp6::hdr_min_len());
    p->data = raw_pkt + icmp6::hdr_min_len();

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP type: %d   code: %d\n",
                p->icmp6h->type, p->icmp6h->code););

    switch(p->icmp6h->type)
    {
        case icmp6::Icmp6Types::ECHO:
        case icmp6::Icmp6Types::REPLY:
            if (p->dsize >= sizeof(ICMPHdr::icmp_hun.idseq))
            {
                /* Set data pointer to that of the "echo message" */
                /* add the size of the echo ext to the data
                 * ptr and subtract it from the data size */
                p->dsize -= sizeof(ICMPHdr::icmp_hun.idseq);
                p->data += sizeof(ICMPHdr::icmp_hun.idseq);

                if ( ipv6::is_multicast(p->ip6h->ip_dst.ip.u6_addr8[0]) )
                    codec_events::decoder_event(p, DECODE_ICMP6_DST_MULTICAST);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "WARNING: Truncated ICMP Echo header (%d bytes).\n", len););

                codec_events::decoder_event(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
                p->icmp6h = NULL;
//                dc.discards++;
//                dc.icmpdisc++;
                return false;
            }
            break;

        case ICMP6_BIG:
//        case icmp6::Icmp6Types::BIG:  --> naming conflict with a different macro in byte_exter.h
            if (p->dsize >= sizeof(ICMP6TooBig))
            {
                ICMP6TooBig *too_big = (ICMP6TooBig *)raw_pkt;
                /* Set data pointer past MTU */
                p->data += 4;
                p->dsize -= 4;

                if (ntohl(too_big->mtu) < 1280)
                {
                    codec_events::decoder_event(p, DECODE_ICMPV6_TOO_BIG_BAD_MTU);
                }
                lyr_len = icmp6::hdr_normal_len();
                DecodeICMPEmbeddedIP6(p->data, p->dsize, p);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "WARNING: Truncated ICMP header (%d bytes).\n", len););

                codec_events::decoder_event(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
                p->icmp6h = NULL;
//                dc.discards++;
//                dc.icmpdisc++;
                return false;
            }
            break;

        case icmp6::Icmp6Types::TIME:
        case icmp6::Icmp6Types::PARAMS:
        case icmp6::Icmp6Types::UNREACH:
            if (p->dsize >= 4)
            {
                /* Set data pointer past the 'unused/mtu/pointer block */
                p->data += 4;
                p->dsize -= 4;

                if (p->icmp6h->type == ICMP6_UNREACH)
                {
                    if (p->icmp6h->code == 2)
                    {
                        codec_events::decoder_event(p, DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE);
                    }
                    else if (p->icmp6h->code > 6)
                    {
                        codec_events::decoder_event(p, DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE);
                    }
                }
                lyr_len = icmp6::hdr_normal_len();
                DecodeICMPEmbeddedIP6(p->data, p->dsize, p);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "WARNING: Truncated ICMP header (%d bytes).\n", len););

                codec_events::decoder_event(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
                p->icmp6h = NULL;
//                dc.discards++;
//                dc.icmpdisc++;
                return false;
            }
            break;

        case icmp6::Icmp6Types::ADVERTISEMENT:
            if (p->dsize >= (sizeof(ICMP6RouterAdvertisement) - icmp6::hdr_min_len()))
            {
                ICMP6RouterAdvertisement *ra = (ICMP6RouterAdvertisement *)raw_pkt;
                if (p->icmp6h->code != 0)
                {
                    codec_events::decoder_event(p, DECODE_ICMPV6_ADVERT_BAD_CODE);
                }
                if (ntohl(ra->reachable_time) > 3600000)
                {
                    codec_events::decoder_event(p, DECODE_ICMPV6_ADVERT_BAD_REACHABLE);
                }
                lyr_len = icmp6::hdr_min_len();
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "WARNING: Truncated ICMP header (%d bytes).\n", len););

                codec_events::decoder_event(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
                p->icmp6h = NULL;
//                dc.discards++;
//                dc.icmpdisc++;
                return false;
            }
            break;

        case icmp6::Icmp6Types::SOLICITATION:
            if (p->dsize >= (sizeof(ICMP6RouterSolicitation) - icmp6::hdr_min_len()))
            {
                ICMP6RouterSolicitation *rs = (ICMP6RouterSolicitation *)raw_pkt;
                if (rs->code != 0)
                {
                    codec_events::decoder_event(p, DECODE_ICMPV6_SOLICITATION_BAD_CODE);
                }
                if (ntohl(rs->reserved) != 0)
                {
                    codec_events::decoder_event(p, DECODE_ICMPV6_SOLICITATION_BAD_RESERVED);
                }
                lyr_len = icmp6::hdr_min_len();
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "WARNING: Truncated ICMP header (%d bytes).\n", len););

                codec_events::decoder_event(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
                p->icmp6h = NULL;
//                dc.discards++;
//                dc.icmpdisc++;
                return false;
            }
            break;

        case icmp6::Icmp6Types::NODE_INFO_QUERY:
        case icmp6::Icmp6Types::NODE_INFO_RESPONSE:
            if (p->dsize >= (sizeof(ICMP6NodeInfo) - icmp6::hdr_min_len()))
            {
                ICMP6NodeInfo *ni = (ICMP6NodeInfo *)raw_pkt;
                if (ni->code > 2)
                {
                    codec_events::decoder_event(p, DECODE_ICMPV6_NODE_INFO_BAD_CODE);
                }
                /* TODO: Add alert for INFO Response, code == 1 || code == 2)
                 * and there is data.
                 */
                 lyr_len = icmp6::hdr_min_len();
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "WARNING: Truncated ICMP header (%d bytes).\n", len););

                codec_events::decoder_event(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
                p->icmp6h = NULL;
//                dc.discards++;
//                dc.icmpdisc++;
                return false;
            }
            break;

        default:
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "WARNING: ICMP6_TYPE (type %d).\n", p->icmp6h->type););
            codec_events::decoder_event(p, DECODE_ICMP6_TYPE_OTHER);

            lyr_len = icmp6::hdr_min_len();
            break;
    }

    p->proto_bits |= PROTO_BIT__ICMP;
    p->proto_bits &= ~(PROTO_BIT__UDP | PROTO_BIT__TCP);
    return true;
}



/*
 * Function: DecodeICMPEmbeddedIP6(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the ICMP embedded IP6 header + payload
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to dummy packet decode struct
 *
 * Returns: void function
 */
static void DecodeICMPEmbeddedIP6(const uint8_t *pkt, const uint32_t len, Packet *p)
{
//    uint16_t orig_frag_offset;

    /* lay the IP struct over the raw data */
    ipv6::IP6RawHdr* hdr = (ipv6::IP6RawHdr*)pkt;
//    dc.embdip++;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "DecodeICMPEmbeddedIP6: ip header"
                    " starts at: %p, length is %lu\n", hdr,
                    (unsigned long) len););

    /* do a little validation */
    if ( len < ipv6::hdr_len() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP6: IP short header (%d bytes)\n", len););

        codec_events::decoder_event(p, DECODE_ICMP_ORIG_IP_TRUNCATED);

//        dc.discards++;
        return;
    }

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if(IPRAW_HDR_VER(hdr) != 6)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP: not IPv6 datagram ([ver: 0x%x][len: 0x%x])\n",
            IPRAW_HDR_VER(hdr), len););

        codec_events::decoder_event(p, DECODE_ICMP_ORIG_IP_VER_MISMATCH);

//        dc.discards++;
        return;
    }

    if ( len < ipv6::hdr_len() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP6: IP6 len (%d bytes) < IP6 hdr len (%d bytes), packet discarded\n",
            len, ipv6::hdr_len()););

        codec_events::decoder_event(p, DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP);

//        dc.discards++;
        return;
    }
    sfiph_orig_build(p, pkt, AF_INET6);

//    orig_frag_offset = ntohs(GET_ORIG_IPH_OFF(p));
//    orig_frag_offset &= 0x1FFF;

    // XXX NOT YET IMPLEMENTED - fragments inside ICMP payload

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP6 Unreachable IP6 header length: "
                            "%lu\n", (unsigned long)ipv6::hdr_len()););

    switch(GET_ORIG_IPH_PROTO(p))
    {
        case IPPROTO_TCP: /* decode the interesting part of the header */
            p->orig_tcph = (TCPHdr *)(pkt + ipv6::hdr_len());

            /* stuff more data into the printout data struct */
            p->orig_sp = ntohs(p->orig_tcph->th_sport);
            p->orig_dp = ntohs(p->orig_tcph->th_dport);

            break;

        case IPPROTO_UDP:
            p->orig_udph = (udp::UDPHdr *)(pkt + ipv6::hdr_len());

            /* fill in the printout data structs */
            p->orig_sp = ntohs(p->orig_udph->uh_sport);
            p->orig_dp = ntohs(p->orig_udph->uh_dport);

            break;

        case IPPROTO_ICMP:
            p->orig_icmph = (ICMPHdr *)(pkt + ipv6::hdr_len());
            break;
    }

    return;
}


/******************************************************************
 ******************** E N C O D E R  ******************************
 ******************************************************************/


namespace
{

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint32_t unused;
} IcmpHdr;

} // namespace


bool Icmp6Codec::encode (EncState* enc, Buffer* out, const uint8_t *raw_in)
{
    checksum::Pseudoheader6 ps6;
    IcmpHdr* ho;

    // ip + udp headers are copied separately because there
    // may be intervening extension headers which aren't copied


    // copy first 8 octets of original ip data (ie udp header)
    // TBD: copy up to minimum MTU worth of data
    if (!update_buffer(out, icmp4::unreach_data()))
        return false;
    memcpy(out->base, raw_in, icmp4::unreach_data());


    // copy original ip header
    if (!update_buffer(out, enc->ip_len))
        return false;

    // TBD should be able to elminate enc->ip_hdr by using layer-2
    memcpy(out->base, enc->ip_hdr, enc->ip_len);
    ((ipv6::IP6RawHdr*)out->base)->ip6nxt = IPPROTO_UDP;


    if (!update_buffer(out, sizeof(*ho)))
        return false;

    ho = reinterpret_cast<IcmpHdr*>(out->base);
    ho->type = 1;   // dest unreachable
    ho->code = 4;   // port unreachable
    ho->cksum = 0;
    ho->unused = 0;

    int len;

#ifdef DEBUG
    if ( (int)enc->type < (int) EncodeType::ENC_UNR_NET )
        return false;
#endif

    enc->proto = IPPROTO_ICMPV6;


    len = buff_diff(out, (uint8_t *)ho);

    memcpy(ps6.sip, ((ipv6::IP6RawHdr *)enc->ip_hdr)->ip6_src.s6_addr, sizeof(ps6.sip));
    memcpy(ps6.dip, ((ipv6::IP6RawHdr *)enc->ip_hdr)->ip6_dst.s6_addr, sizeof(ps6.dip));
    ps6.zero = 0;
    ps6.protocol = IPPROTO_ICMPV6;
    ps6.len = htons((uint16_t)(len));

    ho->cksum = checksum::icmp_cksum((uint16_t *)ho, len, &ps6);

    return true;
}

bool Icmp6Codec::update (Packet* p, Layer* lyr, uint32_t* len)
{
    IcmpHdr* h = (IcmpHdr*)(lyr->start);

    *len += sizeof(*h) + p->dsize;

    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) ) {
        checksum::Pseudoheader6 ps6;
        h->cksum = 0;

        memcpy(ps6.sip, &p->ip6h->ip_src.ip32, sizeof(ps6.sip));
        memcpy(ps6.dip, &p->ip6h->ip_dst.ip32, sizeof(ps6.dip));
        ps6.zero = 0;
        ps6.protocol = IPPROTO_ICMPV6;
        ps6.len = htons((uint16_t)*len);
        h->cksum = checksum::icmp_cksum((uint16_t *)h, *len, &ps6);
    }

    return true;
}

void Icmp6Codec::format (EncodeFlags, const Packet*, Packet* c, Layer* lyr)
{
    // TBD handle nested icmp6 layers
    c->icmp6h = (ICMP6Hdr*)lyr->start;
}

#if 0

/*
 * CHECKSUM
 */


/*
*  checksum icmp6
*/

static unsigned short in_chksum_icmp6(pseudoheader6 *ph,
     unsigned short *w, int blen )
{
  uint16_t *h = (uint16_t *)ph;
  unsigned  short answer=0;
  unsigned int cksum = 0;

  /* PseudoHeader must have 36 bytes */
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

  while(blen >=32)
  {
     cksum += w[0];
     cksum += w[1];
     cksum += w[2];
     cksum += w[3];
     cksum += w[4];
     cksum += w[5];
     cksum += w[6];
     cksum += w[7];
     cksum += w[8];
     cksum += w[9];
     cksum += w[10];
     cksum += w[11];
     cksum += w[12];
     cksum += w[13];
     cksum += w[14];
     cksum += w[15];
     w     += 16;
     blen  -= 32;
  }

  while(blen >=8)
  {
     cksum += w[0];
     cksum += w[1];
     cksum += w[2];
     cksum += w[3];
     w     += 4;
     blen  -= 8;
  }

  while(blen > 1)
  {
     cksum += *w++;
     blen  -= 2;
  }

  if( blen == 1 )
  {
    *(unsigned char*)(&answer) = (*(unsigned char*)w);
    cksum += answer;
  }

  cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
  cksum += (cksum >> 16);


  return (unsigned short)(~cksum);
}
#endif


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static Codec* ctor()
{
    return new Icmp6Codec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const char* name = "icmp6";

static const CodecApi ipv6_api =
{
    {
        PT_CODEC,
        name,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr,
    },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
};


const BaseApi* cd_icmp6 = &ipv6_api.base;
