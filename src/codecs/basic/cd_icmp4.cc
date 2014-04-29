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
// cd_icmp4.cc author Josh Rosenbaum <jorosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

#include "snort.h"
#include "codecs/decode_module.h"
#include "protocols/icmp4.h"
#include "events/codec_events.h"


namespace{

const uint32_t ICMP_HEADER_LEN = 4;
const uint32_t ICMP_NORMAL_LEN = 8;


class Icmp4Codec : public Codec{

public:
    Icmp4Codec() : Codec("icmp4"){};
    ~Icmp4Codec() {};
    
    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual bool decode(const uint8_t* raw_packet, const uint32_t raw_len, 
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id);


    // DELETE from here and below
    #include "codecs/sf_protocols.h"
    virtual inline PROTO_ID get_proto_id() { return PROTO_ICMP4; };

private:

    void DecodeICMPEmbeddedIP(const uint8_t *pkt, const uint32_t len, Packet *p);
    void ICMP4AddrTests (Packet* );
    void ICMP4MiscTests (Packet *);

};

} // namespace


void Icmp4Codec::get_protocol_ids(std::vector<uint16_t> &v)
{
    v.push_back(IPPROTO_ICMP);
}




//--------------------------------------------------------------------
// decode.c::ICMP
//--------------------------------------------------------------------

/*
 * Function: DecodeICMP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the ICMP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the decoded packet struct
 *
 * Returns: void function
 */
bool Icmp4Codec::decode(const uint8_t* raw_pkt, const uint32_t raw_len, 
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    if(raw_len < ICMP_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "WARNING: Truncated ICMP4 header (%d bytes).\n", raw_len););

        codec_events::decoder_event(p, DECODE_ICMP4_HDR_TRUNC);

//        p->icmph = NULL;
//        dc.discards++;
//        dc.icmpdisc++;

        return false;
    }

    /* set the header ptr first */

    p->icmph = reinterpret_cast<ICMPHdr *>(const_cast<uint8_t *> (raw_pkt));

    switch (p->icmph->type)
    {
            // fall through ...
        case icmp4::IcmpType::SOURCE_QUENCH:
        case icmp4::IcmpType::DEST_UNREACH:
        case icmp4::IcmpType::REDIRECT:
        case icmp4::IcmpType::TIME_EXCEEDED:
        case icmp4::IcmpType::PARAMETERPROB:
        case icmp4::IcmpType::ECHOREPLY:
        case icmp4::IcmpType::ECHO:
        case icmp4::IcmpType::ROUTER_ADVERTISE:
        case icmp4::IcmpType::ROUTER_SOLICIT:
        case icmp4::IcmpType::INFO_REQUEST:
        case icmp4::IcmpType::INFO_REPLY:
            if (raw_len < 8)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "Truncated ICMP header(%d bytes)\n", raw_len););

                codec_events::decoder_event(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
//                dc.discards++;
//                dc.icmpdisc++;

                return false;
            }
            break;

        case icmp4::IcmpType::TIMESTAMP:
        case icmp4::IcmpType::TIMESTAMPREPLY:
            if (raw_len < 20)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "Truncated ICMP header(%d bytes)\n", raw_len););

                codec_events::decoder_event(p, DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR);

                p->icmph = NULL;
//                dc.discards++;
//                dc.icmpdisc++;

                return false;
            }
            break;

        case icmp4::IcmpType::ADDRESS:
        case icmp4::IcmpType::ADDRESSREPLY:
            if (raw_len < 12)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "Truncated ICMP header(%d bytes)\n", raw_len););


                codec_events::decoder_event(p, DECODE_ICMP_DGRAM_LT_ADDRHDR);

                p->icmph = NULL;
//                dc.discards++;
//                dc.icmpdisc++;

                return false;
            }
            break;

        default:
            codec_events::decoder_event(p, DECODE_ICMP4_TYPE_OTHER);
            break;
    }


    if (ScIcmpChecksums())
    {
        uint16_t csum = icmp4::in_chksum_icmp((uint16_t *)p->icmph, raw_len);

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

    lyr_len = ICMP_HEADER_LEN;

    p->dsize = (u_short)(raw_len - ICMP_HEADER_LEN);
    p->data = raw_pkt + ICMP_HEADER_LEN;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP type: %d   code: %d\n",
                p->icmph->type, p->icmph->code););

    switch(p->icmph->type)
    {
        case icmp4::IcmpType::ECHO:
            ICMP4AddrTests(p);
        // fall through ...

        case icmp4::IcmpType::ECHOREPLY:
            /* setup the pkt id and seq numbers */
            /* add the size of the echo ext to the data
             * ptr and subtract it from the data size */
            lyr_len += sizeof(ICMPHdr::icmp_hun.idseq);
            break;

        case icmp4::IcmpType::DEST_UNREACH:
            if ((p->icmph->code == icmp4::IcmpCode::FRAG_NEEDED)
                    && (ntohs(p->icmph->s_icmp_nextmtu) < 576))
            {
                codec_events::decoder_event(p, DECODE_ICMP_PATH_MTU_DOS);
            }

            /* Fall through */

        case icmp4::IcmpType::SOURCE_QUENCH:
        case icmp4::IcmpType::REDIRECT:
        case icmp4::IcmpType::TIME_EXCEEDED:
        case icmp4::IcmpType::PARAMETERPROB:
            /* account for extra 4 bytes in header */
            lyr_len += 4;
            DecodeICMPEmbeddedIP(raw_pkt + lyr_len,  raw_len - lyr_len, p);
            break;

        default:
            break;
    }


    /* Run a bunch of ICMP decoder rules */
    p->dsize = (u_short)(raw_len - lyr_len);
    p->data = raw_pkt + lyr_len;
    ICMP4MiscTests(p);

    p->proto_bits |= PROTO_BIT__ICMP;
    p->proto_bits &= ~(PROTO_BIT__UDP | PROTO_BIT__TCP);

    next_prot_id = -1;
    return true;
}


/*
 * Function: DecodeICMPEmbeddedIP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the ICMP embedded IP header + 64 bits payload
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to dummy packet decode struct
 *
 * Returns: void function
 */
void Icmp4Codec::DecodeICMPEmbeddedIP(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    uint32_t ip_len;       /* length from the start of the ip hdr to the
                             * pkt end */
    uint32_t hlen;             /* ip header length */
    uint16_t orig_frag_offset;

    /* do a little validation */
    if(len < ipv4::hdr_len())
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP: IP short header (%d bytes)\n", len););

        codec_events::decoder_event(p, DECODE_ICMP_ORIG_IP_TRUNCATED);

        p->orig_family = NO_IP;
        p->orig_iph = NULL;
        return;
    }

    /* lay the IP struct over the raw data */
    sfiph_orig_build(p, pkt, AF_INET);
    p->orig_iph = (IPHdr *) pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "DecodeICMPEmbeddedIP: ip header"
                    " starts at: %p, length is %lu\n", p->orig_iph,
                    (unsigned long) len););
    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if((GET_ORIG_IPH_VER(p) != 4) && !IS_IP6(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP: not IPv4 datagram ([ver: 0x%x][len: 0x%x])\n",
            GET_ORIG_IPH_VER(p), GET_ORIG_IPH_LEN(p)););

        codec_events::decoder_event(p, DECODE_ICMP_ORIG_IP_VER_MISMATCH);

        p->orig_family = NO_IP;
        p->orig_iph = NULL;
        return;
    }

    /* set the IP datagram length */
    ip_len = ntohs(GET_ORIG_IPH_LEN(p));

    /* set the IP header length */
    hlen = (p->orig_ip4h->ip_verhl & 0x0f) << 2;

    if(len < hlen)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP: IP len (%d bytes) < IP hdr len (%d bytes), packet discarded\n",
            ip_len, hlen););

        codec_events::decoder_event(p, DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP);

        p->orig_family = NO_IP;
        p->orig_iph = NULL;
        return;
    }

    /* set the remaining packet length */
    ip_len = len - hlen;

    orig_frag_offset = ntohs(GET_ORIG_IPH_OFF(p));
    orig_frag_offset &= 0x1FFF;

    if (orig_frag_offset == 0)
    {
        /* Original IP payload should be 64 bits */
        if (ip_len < 8)
        {
            codec_events::decoder_event(p, DECODE_ICMP_ORIG_PAYLOAD_LT_64);

            return;
        }
        /* ICMP error packets could contain as much of original payload
         * as possible, but not exceed 576 bytes
         */
        else if (ntohs(GET_IPH_LEN(p)) > 576)
        {
            codec_events::decoder_event(p, DECODE_ICMP_ORIG_PAYLOAD_GT_576);
        }
    }
    else
    {
        /* RFC states that only first frag will get an ICMP response */
        codec_events::decoder_event(p, DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET);
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP Unreachable IP header length: "
                            "%lu\n", (unsigned long)hlen););

    switch(GET_ORIG_IPH_PROTO(p))
    {
        case IPPROTO_TCP: /* decode the interesting part of the header */
            p->orig_tcph = (TCPHdr *)(pkt + hlen);

            /* stuff more data into the printout data struct */
            p->orig_sp = ntohs(p->orig_tcph->th_sport);
            p->orig_dp = ntohs(p->orig_tcph->th_dport);

            break;

        case IPPROTO_UDP:
            p->orig_udph = (udp::UDPHdr *)(pkt + hlen);

            /* fill in the printout data structs */
            p->orig_sp = ntohs(p->orig_udph->uh_sport);
            p->orig_dp = ntohs(p->orig_udph->uh_dport);

            break;

        case IPPROTO_ICMP:
            p->orig_icmph = (ICMPHdr *)(pkt + hlen);
            break;
    }

    return;
}


void Icmp4Codec::ICMP4AddrTests (Packet* p)
{
    uint8_t msb_dst;

    uint32_t dst = GET_DST_IP(p)->ip32[0];

    // check all 32 bits; all set so byte order is irrelevant ...
    if ( ipv4::is_broadcast(dst) )
        codec_events::decoder_event(p, DECODE_ICMP4_DST_BROADCAST);

    /* - don't use htonl for speed reasons -
     * s_addr is always in network order */
#ifdef WORDS_BIGENDIAN
    msb_dst = (uint8_t)(dst >> 24);
#else
    msb_dst = (uint8_t)(dst & 0xff);
#endif

    // check the 'msn' (most significant nibble) ...
    msb_dst >>= 4;

    if( ipv4::is_multicast(msb_dst) )
        codec_events::decoder_event(p, DECODE_ICMP4_DST_MULTICAST);
}


void Icmp4Codec::ICMP4MiscTests (Packet *p)
{
    if ((p->dsize == 0) &&
        (p->icmph->type == icmp4::IcmpType::ECHO))
        codec_events::decoder_event(p, DECODE_ICMP_PING_NMAP);

    if ((p->dsize == 0) &&
        (p->icmph->s_icmp_seq == 666))
        codec_events::decoder_event(p, DECODE_ICMP_ICMPENUM);

    if ((p->icmph->type == icmp4::IcmpType::REDIRECT) &&
        (p->icmph->code == icmp4::IcmpCode::REDIR_HOST))
        codec_events::decoder_event(p, DECODE_ICMP_REDIRECT_HOST);

    if ((p->icmph->type == icmp4::IcmpType::REDIRECT) &&
        (p->icmph->code == icmp4::IcmpCode::REDIR_NET))
        codec_events::decoder_event(p, DECODE_ICMP_REDIRECT_NET);

    if (p->icmph->type == icmp4::IcmpType::ECHOREPLY)
    {
        int i;
        for (i = 0; i < p->ip_option_count; i++)
        {
            if ( ipv4::is_opt_rr(p->ip_options[i].code) )
                codec_events::decoder_event(p, DECODE_ICMP_TRACEROUTE_IPOPTS);
        }
    }

    if ((p->icmph->type == icmp4::IcmpType::SOURCE_QUENCH) &&
        (p->icmph->code == icmp4::IcmpCode::SOURCE_QUENCH_CODE))
        codec_events::decoder_event(p, DECODE_ICMP_SOURCE_QUENCH);

    if ((p->dsize == 4) &&
        (p->icmph->type == icmp4::IcmpType::ECHO) &&
        (p->icmph->s_icmp_seq == 0) &&
        (p->icmph->code == icmp4::IcmpCode::ECHO_CODE))
        codec_events::decoder_event(p, DECODE_ICMP_BROADSCAN_SMURF_SCANNER);

    if ((p->icmph->type == icmp4::IcmpType::DEST_UNREACH) &&
        (p->icmph->code == icmp4::IcmpCode::PKT_FILTERED))
        codec_events::decoder_event(p, DECODE_ICMP_DST_UNREACH_ADMIN_PROHIBITED);

    if ((p->icmph->type == icmp4::IcmpType::DEST_UNREACH) &&
        (p->icmph->code == icmp4::IcmpCode::PKT_FILTERED_HOST))
        codec_events::decoder_event(p, DECODE_ICMP_DST_UNREACH_DST_HOST_PROHIBITED);

    if ((p->icmph->type == icmp4::IcmpType::DEST_UNREACH) &&
        (p->icmph->code == icmp4::IcmpCode::PKT_FILTERED_NET))
        codec_events::decoder_event(p, DECODE_ICMP_DST_UNREACH_DST_NET_PROHIBITED);
}

/*
 * ENCODER
 */

#if 0

static inline int IcmpCode (EncodeType et) {
    switch ( et ) {
    case EncodeType::ENC_UNR_NET:  return ICMP_UNREACH_NET;
    case EncodeType::ENC_UNR_HOST: return ICMP_UNREACH_HOST;
    case EncodeType::ENC_UNR_PORT: return ICMP_UNREACH_PORT;
    case EncodeType::ENC_UNR_FW:   return ICMP_UNREACH_FILTER_PROHIB;
    default: break;
    }
    return ICMP_UNREACH_PORT;
}


EncStatus UN4_Encode (EncState* enc, Buffer*, Buffer* out)
{
    uint8_t* p;

    uint8_t* hi = enc->p->layers[enc->layer-1].start;
    IcmpHdr* ho = (IcmpHdr*)(out->base + out->end);

#ifdef DEBUG
    if ( (int)enc->type < (int)EncodeType::ENC_UNR_NET )
        return EncStatus::ENC_BAD_OPT;
#endif

    enc->proto = IPPROTO_ICMP;

    UPDATE_BOUND(out, sizeof(*ho));
    ho->type = ICMP_UNREACH;
    ho->code = IcmpCode(enc->type);
    ho->cksum = 0;
    ho->unused = 0;

    // copy original ip header
    p = out->base + out->end;
    UPDATE_BOUND(out, enc->ip_len);
    memcpy(p, enc->ip_hdr, enc->ip_len);

    // copy first 8 octets of original ip data (ie udp header)
    p = out->base + out->end;
    UPDATE_BOUND(out, ICMP_UNREACH_DATA);
    memcpy(p, hi, ICMP_UNREACH_DATA);

    ho->cksum = icmp4::in_chksum_icmp((uint16_t *)ho, BUFF_DIFF(out, ho));

    return EncStatus::ENC_OK;
}

EncStatus ICMP4_Update (Packet* p, Layer* lyr, uint32_t* len)
{
    IcmpHdr* h = (IcmpHdr*)(lyr->start);

    *len += sizeof(*h) + p->dsize;


    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) ) {
        h->cksum = 0;
        h->cksum = icmp4::in_chksum_icmp((uint16_t *)h, *len);
    }

    return EncStatus::ENC_OK;
}

void ICMP4_Format (EncodeFlags, const Packet*, Packet* c, Layer* lyr)
{
    // TBD handle nested icmp4 layers
    c->icmph = (ICMPHdr*)lyr->start;
}
#endif


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec *ctor()
{
    return new Icmp4Codec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const char* name = "icmp4";
static const CodecApi icmp4_api =
{
    { 
        PT_CODEC,
        name,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
};


const BaseApi* cd_icmp4 = &icmp4_api.base;

