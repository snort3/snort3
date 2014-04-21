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

#include <string.h>
#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif


#include "codecs/decode_module.h"
#include "packet_io/sfdaq.h"
#include "sfip/ipv6_port.h" /* #define IpAddrSet */
#include "codecs/codec_events.h"


#include "snort.h"
#include "packet_io/active.h"
#include "protocols/ipv6.h"
#include "protocols/tcp.h"
#include "framework/codec.h"


namespace
{

class TcpCodec : public Codec
{
public:
    TcpCodec() : Codec("Tcp")
    {

    };
    virtual ~TcpCodec(){};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &p_hdr_len, int &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
};

static IpAddrSet *SynToMulticastDstIp = NULL;

} // anonymous namespace



int OptLenValidate(const uint8_t *option_ptr,
                                 const uint8_t *end,
                                 const uint8_t *len_ptr,
                                 int expected_len,
                                 Options *tcpopt,
                                 uint8_t *byte_skip);


static void DecodeTCPOptions(const uint8_t *, uint32_t, Packet *);
static inline void execTcpChksmDrop (void*);
static inline void TCPMiscTests(Packet *p);

static inline unsigned short in_chksum_tcp(pseudoheader *, unsigned short *, int);
static inline unsigned short in_chksum_tcp6(pseudoheader6 *, unsigned short *, int);


/*
 * Function: DecodeTCP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the TCP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => Pointer to packet decode struct
 *
 * Returns: void function
 */
bool TcpCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &p_hdr_len, int &next_prot_id)
{
    uint32_t hlen;            /* TCP header length */

    if(len < tcp::hdr_len())
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "TCP packet (len = %d) cannot contain " "20 byte header\n", len););

        DecoderEvent(p, DECODE_TCP_DGRAM_LT_TCPHDR);

        p->tcph = NULL;
//        dc.discards++;
//        dc.tdisc++;

        return false;
    }

    /* lay TCP on top of the data cause there is enough of it! */
    p->tcph = reinterpret_cast<TCPHdr*>(const_cast<uint8_t*>(raw_pkt));

    /* multiply the payload offset value by 4 */
    p_hdr_len = TCP_OFFSET(p->tcph) << 2;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "TCP th_off is %d, passed len is %lu\n",
                TCP_OFFSET(p->tcph), (unsigned long)len););

    if(p_hdr_len < tcp::hdr_len())
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "TCP Data Offset (%d) < p_hdr_len (%d) \n",
            TCP_OFFSET(p->tcph), p_hdr_len););

        DecoderEvent(p, DECODE_TCP_INVALID_OFFSET);

        p->tcph = NULL;
//        dc.discards++;
//        dc.tdisc++;

        return false;
    }

    if(p_hdr_len > len)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "TCP Data Offset(%d) < longer than payload(%d)!\n",
            TCP_OFFSET(p->tcph) << 2, len););

        DecoderEvent(p, DECODE_TCP_LARGE_OFFSET);

        p->tcph = NULL;
//        dc.discards++;
//        dc.tdisc++;

        return false;
    }

    /* Checksum code moved in front of the other decoder alerts.
       If it's a bad checksum (maybe due to encrypted ESP traffic), the other
       alerts could be false positives. */
    if (ScTcpChecksums())
    {
        uint16_t csum;
        if(IS_IP4(p))
        {
            pseudoheader ph;
            ph.sip = *p->ip4h->ip_src.ip32;
            ph.dip = *p->ip4h->ip_dst.ip32;
            /* setup the pseudo header for checksum calculation */
            ph.zero = 0;
            ph.protocol = GET_IPH_PROTO(p);
            ph.len = htons((u_short)len);

            /* if we're being "stateless" we probably don't care about the TCP
             * checksum, but it's not bad to keep around for shits and giggles */
            /* calculate the checksum */
            csum = in_chksum_tcp(&ph, (uint16_t *)(p->tcph), len);
        }
        /* IPv6 traffic */
        else
        {
            pseudoheader6 ph6;
            COPY4(ph6.sip, p->ip6h->ip_src.ip32);
            COPY4(ph6.dip, p->ip6h->ip_dst.ip32);
            ph6.zero = 0;
            ph6.protocol = GET_IPH_PROTO(p);
            ph6.len = htons((u_short)len);

            csum = in_chksum_tcp6(&ph6, (uint16_t *)(p->tcph), len);
        }

        if(csum)
        {
            /* Don't drop the packet if this is encapuslated in Teredo or ESP.
               Just get rid of the TCP header and stop decoding. */
            if (p->packet_flags & PKT_UNSURE_ENCAP)
            {
                p->tcph = NULL;
                return false;
            }

            p->error_flags |= PKT_ERR_CKSUM_TCP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad TCP checksum\n",
                                    "0x%x versus 0x%x\n", csum,
                                    ntohs(p->tcph->th_sum)););

            CodecEvents::exec_tcp_chksm_drop(p);
//            dc.invalid_checksums++;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"TCP Checksum: OK\n"););
        }
    }

    if(TCP_ISFLAGSET(p->tcph, (TH_FIN|TH_PUSH|TH_URG)))
    {
        if(TCP_ISFLAGSET(p->tcph, (TH_SYN|TH_ACK|TH_RST)))
        {
            DecoderEvent(p, DECODE_TCP_XMAS);
        }
        else
        {
            DecoderEvent(p, DECODE_TCP_NMAP_XMAS);
        }
        // Allowing this packet for further processing
        // (in case there is a valid data inside it).
        /*p->tcph = NULL;
        dc.discards++;
        dc.tdisc++;
        return;*/
    }

    if(TCP_ISFLAGSET(p->tcph, (TH_SYN)))
    {
        /* check if only SYN is set */
        if( p->tcph->th_flags == TH_SYN )
        {
            if( p->tcph->th_seq == 6060842 )
            {
                if( GET_IPH_ID(p) == 413 )
                {
                    DecoderEvent(p, DECODE_DOS_NAPTHA);
                }
            }
        }

        if( IpAddrSetContains(SynToMulticastDstIp, GET_DST_ADDR(p)) )
        {
            DecoderEvent(p, DECODE_SYN_TO_MULTICAST);
        }
        if ( (p->tcph->th_flags & TH_RST) )
            DecoderEvent(p, DECODE_TCP_SYN_RST);

        if ( (p->tcph->th_flags & TH_FIN) )
            DecoderEvent(p, DECODE_TCP_SYN_FIN);
    }
    else
    {   // we already know there is no SYN
        if ( !(p->tcph->th_flags & (TH_ACK|TH_RST)) )
            DecoderEvent(p, DECODE_TCP_NO_SYN_ACK_RST);
    }

    if ( (p->tcph->th_flags & (TH_FIN|TH_PUSH|TH_URG)) &&
        !(p->tcph->th_flags & TH_ACK) )
        DecoderEvent(p, DECODE_TCP_MUST_ACK);

    /* stuff more data into the printout data struct */
    p->sp = ntohs(p->tcph->th_sport);
    p->dp = ntohs(p->tcph->th_dport);


    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "tcp header starts at: %p\n", p->tcph););

//    PushLayer(PROTO_TCP, p, pkt, p_hdr_len);
    next_prot_id = -1;

    /* if options are present, decode them */
    p->tcp_options_len = (uint16_t)(p_hdr_len - tcp::hdr_len());

    if(p->tcp_options_len > 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "%lu bytes of tcp options....\n",
                    (unsigned long)(p->tcp_options_len)););

        p->tcp_options_data = raw_pkt + tcp::hdr_len();
        DecodeTCPOptions((uint8_t *) (raw_pkt + tcp::hdr_len()), p->tcp_options_len, p);
    }
    else
    {
        p->tcp_option_count = 0;
    }

    /* set the data pointer and size */
    p->data = (uint8_t *) (raw_pkt + p_hdr_len);

    if(p_hdr_len < len)
    {
        p->dsize = (u_short)(len - p_hdr_len);
    }
    else
    {
        p->dsize = 0;
    }

    if ( (p->tcph->th_flags & TH_URG) &&
        (!p->dsize || ntohs(p->tcph->th_urp) > p->dsize) )
        DecoderEvent(p, DECODE_TCP_BAD_URP);

    p->proto_bits |= PROTO_BIT__TCP;

    if (ScIgnoreTcpPort(p->sp) || ScIgnoreTcpPort(p->dp))
        p->packet_flags |= PKT_IGNORE;
    else
        TCPMiscTests(p);
    
    return true;
}



/*
 * Function: DecodeTCPOptions(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Fairly self explainatory name, don't you think?
 *
 *          TCP Option Header length validation is left to the caller
 *
 *          For a good listing of TCP Options,
 *          http://www.iana.org/assignments/tcp-parameters
 *
 *   ------------------------------------------------------------
 *   From: "Kastenholz, Frank" <FKastenholz@unispherenetworks.com>
 *   Subject: Re: skeeter & bubba TCP options?
 *
 *   ah, the sins of ones youth that never seem to be lost...
 *
 *   it was something that ben levy and stev and i did at ftp many
 *   many moons ago. bridgham and stev were the instigators of it.
 *   the idea was simple, put a dh key exchange directly in tcp
 *   so that all tcp sessions could be encrypted without requiring
 *   any significant key management system. authentication was not
 *   a part of the idea, it was to be provided by passwords or
 *   whatever, which could now be transmitted over the internet
 *   with impunity since they were encrypted... we implemented
 *   a simple form of this (doing the math was non trivial on the
 *   machines of the day). it worked. the only failure that i
 *   remember was that it was vulnerable to man-in-the-middle
 *   attacks.
 *
 *   why "skeeter" and "bubba"? well, that's known only to stev...
 *   ------------------------------------------------------------
 *
 * 4.2.2.5 TCP Options: RFC-793 Section 3.1
 *
 *    A TCP MUST be able to receive a TCP option in any segment. A TCP
 *    MUST ignore without error any TCP option it does not implement,
 *    assuming that the option has a length field (all TCP options
 *    defined in the future will have length fields). TCP MUST be
 *    prepared to handle an illegal option length (e.g., zero) without
 *    crashing; a suggested procedure is to reset the connection and log
 *    the reason.
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *            p     => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeTCPOptions(const uint8_t *start, uint32_t o_len, Packet *p)
{
    const uint8_t *option_ptr = start;
    const uint8_t *end_ptr = start + o_len; /* points to byte after last option */
    const uint8_t *len_ptr;
    uint8_t opt_count = 0;
    u_char done = 0; /* have we reached TCPOPT_EOL yet?*/
    u_char experimental_option_found = 0;      /* are all options RFC compliant? */
    u_char obsolete_option_found = 0;
    u_char ttcp_found = 0;

    int code = 2;
    uint8_t byte_skip;

    /* Here's what we're doing so that when we find out what these
     * other buggers of TCP option codes are, we can do something
     * useful
     *
     * 1) get option code
     * 2) check for enough space for current option code
     * 3) set option data ptr
     * 4) increment option code ptr
     *
     * TCP_OPTLENMAX = 40 because of
     *        (((2^4) - 1) * 4  - tcp::hdr_len)
     *
     */

    if(o_len > TCP_OPTLENMAX)
    {
        /* This shouldn't ever alert if we are doing our job properly
         * in the caller */
        p->tcph = NULL; /* let's just alert */
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                                "o_len(%u) > TCP_OPTLENMAX(%u)\n",
                                o_len, TCP_OPTLENMAX));
        return;
    }

    while((option_ptr < end_ptr) && (opt_count < TCP_OPTLENMAX) && !done)
    {
        p->tcp_options[opt_count].code = *option_ptr;

        if((option_ptr + 1) < end_ptr)
        {
            len_ptr = option_ptr + 1;
        }
        else
        {
            len_ptr = NULL;
        }

        switch(*option_ptr)
        {
        case tcp::TcpOpt::EOL:
            done = 1; /* fall through to the NOP case */
        case tcp::TcpOpt::NOP:
            p->tcp_options[opt_count].len = 0;
            p->tcp_options[opt_count].data = NULL;
            byte_skip = 1;
            code = 0;
            break;
        case tcp::TcpOpt::MAXSEG:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_MAXSEG,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case tcp::TcpOpt::SACKOK:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_SACKOK,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case tcp::TcpOpt::WSCALE:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_WSCALE,
                                  &p->tcp_options[opt_count], &byte_skip);
            if (code == 0)
            {
                if (
                    ((uint16_t) p->tcp_options[opt_count].data[0] > 14))
                {
                    /* LOG INVALID WINDOWSCALE alert */
                    DecoderEvent(p, DECODE_TCPOPT_WSCALE_INVALID);
                }
            }
            break;
        case tcp::TcpOpt::ECHO: /* both use the same lengths */
        case tcp::TcpOpt::ECHOREPLY:
            obsolete_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_ECHO,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case tcp::TcpOpt::MD5SIG:
            /* RFC 5925 obsoletes this option (see below) */
            obsolete_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_MD5SIG,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case tcp::TcpOpt::AUTH:
            /* Has to have at least 4 bytes - see RFC 5925, Section 2.2 */
            if ((len_ptr != NULL) && (*len_ptr < 4))
                code = tcp::OPT_BADLEN;
            else
                code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                        &p->tcp_options[opt_count], &byte_skip);
            break;
        case tcp::TcpOpt::SACK:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->tcp_options[opt_count], &byte_skip);
            if((code == 0) && (p->tcp_options[opt_count].data == NULL))
                code = tcp::OPT_BADLEN;

            break;
        case tcp::TcpOpt::CC_ECHO:
            ttcp_found = 1;
            /* fall through */
        case tcp::TcpOpt::CC:  /* all 3 use the same lengths / T/TCP */
        case tcp::TcpOpt::CC_NEW:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_CC,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case tcp::TcpOpt::TRAILER_CSUM:
            experimental_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_TRAILER_CSUM,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;

        case tcp::TcpOpt::TIMESTAMP:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_TIMESTAMP,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;

        case tcp::TcpOpt::SKEETER:
        case tcp::TcpOpt::BUBBA:
        case tcp::TcpOpt::UNASSIGNED:
            obsolete_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        default:
        case tcp::TcpOpt::SCPS:
        case tcp::TcpOpt::SELNEGACK:
        case tcp::TcpOpt::RECORDBOUND:
        case tcp::TcpOpt::CORRUPTION:
        case tcp::TcpOpt::PARTIAL_PERM:
        case tcp::TcpOpt::PARTIAL_SVC:
        case tcp::TcpOpt::ALTCSUM:
        case tcp::TcpOpt::SNAP:
            experimental_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        }

        if(code < 0)
        {
            if(code == tcp::OPT_BADLEN)
            {
                DecoderEvent(p, DECODE_TCPOPT_BADLEN);
            }
            else if(code == tcp::OPT_TRUNC)
            {
                DecoderEvent(p, DECODE_TCPOPT_TRUNCATED);
            }

            /* set the option count to the number of valid
             * options found before this bad one
             * some implementations (BSD and Linux) ignore
             * the bad ones, but accept the good ones */
            p->tcp_option_count = opt_count;

            return;
        }

        opt_count++;

        option_ptr += byte_skip;
    }

    p->tcp_option_count = opt_count;

    if (experimental_option_found)
    {
        DecoderEvent(p, DECODE_TCPOPT_EXPERIMENTAL);
    }
    else if (obsolete_option_found)
    {
        DecoderEvent(p, DECODE_TCPOPT_OBSOLETE);
    }
    else if (ttcp_found)
    {
        DecoderEvent(p, DECODE_TCPOPT_TTCP);
    }

    return;
}



/* TCP-layer decoder alerts */
static inline void TCPMiscTests(Packet *p)
{
    if ( ((p->tcph->th_flags & TH_NORESERVED) == TH_SYN ) &&
         (p->tcph->th_seq == htonl(674711609)) )
        DecoderEvent(p, DECODE_TCP_SHAFT_SYNFLOOD);

    if (p->sp == 0 || p->dp == 0)
        DecoderEvent(p, DECODE_TCP_PORT_ZERO);
}



static inline void execTcpChksmDrop (void*)
{
    if( ScInlineMode() && ScTcpChecksumDrops() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Dropping bad packet (TCP checksum)\n"););
        Active_DropPacket();
    }
}

/*
 *  ENCODER
 */

#if 0

//-------------------------------------------------------------------------
// TCP
// encoder creates TCP RST
// should always try to use acceptable ack since we send RSTs in a
// stateless fashion ... from rfc 793:
//
// In all states except SYN-SENT, all reset (RST) segments are validated
// by checking their SEQ-fields.  A reset is valid if its sequence number
// is in the window.  In the SYN-SENT state (a RST received in response
// to an initial SYN), the RST is acceptable if the ACK field
// acknowledges the SYN.
//-------------------------------------------------------------------------

EncStatus TCP_Encode (EncState* enc, Buffer* in, Buffer* out)
{
    int len, ctl;

    TCPHdr* hi = (TCPHdr*)enc->p->layers[enc->layer-1].start;
    TCPHdr* ho = (TCPHdr*)(out->base + out->end);

    UPDATE_BOUND(out, sizeof(*ho));

    len = GET_TCP_HDR_LEN(hi) - sizeof(*hi);
    UPDATE_BOUND(in, len);
    ctl = (hi->th_flags & TH_SYN) ? 1 : 0;

    if ( FORWARD(enc) )
    {
        ho->th_sport = hi->th_sport;
        ho->th_dport = hi->th_dport;

        // th_seq depends on whether the data passes or drops
        if ( DAQ_GetInterfaceMode(enc->p->pkth) != DAQ_MODE_INLINE )
            ho->th_seq = htonl(ntohl(hi->th_seq) + enc->p->dsize + ctl);
        else
            ho->th_seq = hi->th_seq;

        ho->th_ack = hi->th_ack;
    }
    else
    {
        ho->th_sport = hi->th_dport;
        ho->th_dport = hi->th_sport;

        ho->th_seq = hi->th_ack;
        ho->th_ack = htonl(ntohl(hi->th_seq) + enc->p->dsize + ctl);
    }

    if ( enc->flags & ENC_FLAG_SEQ )
    {
        uint32_t seq = ntohl(ho->th_seq);
        seq += (enc->flags & ENC_FLAG_VAL);
        ho->th_seq = htonl(seq);
    }
    ho->th_offx2 = 0;
    SET_TCP_OFFSET(ho, (TCP_HDR_LEN >> 2));
    ho->th_win = ho->th_urp = 0;

    if ( enc->type == EncodeType::ENC_TCP_FIN || 
        enc->type == EncodeType::ENC_TCP_PUSH )
    {
        if ( enc->payLoad && enc->payLen > 0 )
        {
            uint8_t* pdu = out->base + out->end;
            UPDATE_BOUND(out, enc->payLen);
            memcpy(pdu, enc->payLoad, enc->payLen);
        }

        ho->th_flags = TH_ACK;
        if ( enc->type == EncodeType::ENC_TCP_PUSH )
        {
            ho->th_flags |= TH_PUSH;
            ho->th_win = htons(65535);
        }
        else
        {
            ho->th_flags |= TH_FIN;
        }
    }
    else
    {
        ho->th_flags = TH_RST | TH_ACK;
    }

    // in case of ip6 extension headers, this gets next correct
    enc->proto = IPPROTO_TCP;

    ho->th_sum = 0;

    if (IP_VER((IPHdr *)enc->ip_hdr) == 4) {
        pseudoheader ps;
        int len = BUFF_DIFF(out, ho);

        ps.sip = ((IPHdr *)(enc->ip_hdr))->ip_src.s_addr;
        ps.dip = ((IPHdr *)(enc->ip_hdr))->ip_dst.s_addr;
        ps.zero = 0;
        ps.protocol = IPPROTO_TCP;
        ps.len = htons((uint16_t)len);
        ho->th_sum = in_chksum_tcp(&ps, (uint16_t *)ho, len);
    } else {
        pseudoheader6 ps6;
        int len = BUFF_DIFF(out, ho);

        memcpy(ps6.sip, ((ipv6::IP6RawHdr *)enc->ip_hdr)->ip6_src.s6_addr, sizeof(ps6.sip));
        memcpy(ps6.dip, ((ipv6::IP6RawHdr *)enc->ip_hdr)->ip6_dst.s6_addr, sizeof(ps6.dip));
        ps6.zero = 0;
        ps6.protocol = IPPROTO_TCP;
        ps6.len = htons((uint16_t)len);
        ho->th_sum = in_chksum_tcp6(&ps6, (uint16_t *)ho, len);
    }

    return EncStatus::ENC_OK;
}

EncStatus TCP_Update (Packet* p, Layer* lyr, uint32_t* len)
{
    TCPHdr* h = (TCPHdr*)(lyr->start);

    *len += GET_TCP_HDR_LEN(h) + p->dsize;

    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) ) {
        h->th_sum = 0;

        if (IS_IP4(p)) {
            pseudoheader ps;
            ps.sip = ((IPHdr *)(lyr-1)->start)->ip_src.s_addr;
            ps.dip = ((IPHdr *)(lyr-1)->start)->ip_dst.s_addr;
            ps.zero = 0;
            ps.protocol = IPPROTO_TCP;
            ps.len = htons((uint16_t)*len);
            h->th_sum = in_chksum_tcp(&ps, (uint16_t *)h, *len);
        } else {
            pseudoheader6 ps6;
            memcpy(ps6.sip, &p->ip6h->ip_src.ip32, sizeof(ps6.sip));
            memcpy(ps6.dip, &p->ip6h->ip_dst.ip32, sizeof(ps6.dip));
            ps6.zero = 0;
            ps6.protocol = IPPROTO_TCP;
            ps6.len = htons((uint16_t)*len);
            h->th_sum = in_chksum_tcp6(&ps6, (uint16_t *)h, *len);
        }
    }

    return EncStatus::ENC_OK;
}

void TCP_Format (EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    TCPHdr* ch = (TCPHdr*)lyr->start;
    c->tcph = ch;

    if ( REVERSE(f) )
    {
        int i = lyr - c->layers;
        TCPHdr* ph = (TCPHdr*)p->layers[i].start;

        ch->th_sport = ph->th_dport;
        ch->th_dport = ph->th_sport;
    }
    c->sp = ntohs(ch->th_sport);
    c->dp = ntohs(ch->th_dport);
}


#endif 


int OptLenValidate(const uint8_t *option_ptr,
                                 const uint8_t *end,
                                 const uint8_t *len_ptr,
                                 int expected_len,
                                 Options *tcpopt,
                                 uint8_t *byte_skip)
{
    *byte_skip = 0;

    if(len_ptr == NULL)
        return tcp::OPT_TRUNC;


    if(*len_ptr == 0 || expected_len == 0 || expected_len == 1)
    {
        return tcp::OPT_BADLEN;
    }
    else if(expected_len > 1)
    {
        /* not enough data to read in a perfect world */
        if((option_ptr + expected_len) > end)
            return tcp::OPT_TRUNC;

        if(*len_ptr != expected_len)
            return tcp::OPT_BADLEN;
    }
    else /* expected_len < 0 (i.e. variable length) */
    {
        /* RFC sez that we MUST have atleast this much data */
        if(*len_ptr < 2)
            return tcp::OPT_BADLEN;

        /* not enough data to read in a perfect world */
        if((option_ptr + *len_ptr) > end)
            return tcp::OPT_TRUNC;
    }

    tcpopt->len = *len_ptr - 2;

    if(*len_ptr == 2)
        tcpopt->data = NULL;
    else
        tcpopt->data = option_ptr + 2;

    *byte_skip = *len_ptr;

    return 0;
}


/*
 * Checksum Functions
 */

/*
*  checksum tcp
*
*  h    - pseudo header - 12 bytes
*  d    - tcp hdr + payload
*  dlen - length of tcp hdr + payload in bytes
*
*/
static inline unsigned short in_chksum_tcp(pseudoheader *ph,
    unsigned short * d, int dlen )
{
   uint16_t *h = (uint16_t *)ph;
   unsigned int cksum;
   unsigned short answer=0;

   /* PseudoHeader must have 12 bytes */
   cksum  = h[0];
   cksum += h[1];
   cksum += h[2];
   cksum += h[3];
   cksum += h[4];
   cksum += h[5];

   /* TCP hdr must have 20 hdr bytes */
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

   dlen  -= 20; /* bytes   */
   d     += 10; /* short's */

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
    /* printf("new checksum odd byte-packet\n"); */
    *(unsigned char*)(&answer) = (*(unsigned char*)d);

    /* cksum += (uint16_t) (*(uint8_t*)d); */

     cksum += answer;
   }

   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);

   return (unsigned short)(~cksum);
}
/*
*  checksum tcp for IPv6.
*
*  h    - pseudo header - 12 bytes
*  d    - tcp hdr + payload
*  dlen - length of tcp hdr + payload in bytes
*
*/
static inline unsigned short in_chksum_tcp6(pseudoheader6 *ph,
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

   /* TCP hdr must have 20 hdr bytes */
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

   dlen  -= 20; /* bytes   */
   d     += 10; /* short's */

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
    /* printf("new checksum odd byte-packet\n"); */
    *(unsigned char*)(&answer) = (*(unsigned char*)d);

    /* cksum += (uint16_t) (*(uint8_t*)d); */

     cksum += answer;
   }

   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);

   return (unsigned short)(~cksum);
}


/*
 * Static api functions.  there are NOT part of the TCPCodec class,
 * but provide global initializers and/or destructors to the class
 */

static void tcp_codec_ginit()
{
    SynToMulticastDstIp = IpAddrSetParse(snort_conf, "[232.0.0.0/8,233.0.0.0/8,239.0.0.0/8]");


    if( SynToMulticastDstIp == NULL )
        FatalError("Could not initialize SynToMulticastDstIp\n");

}



static void tcp_codec_gterm()
{
    if( SynToMulticastDstIp )
        IpAddrSetDestroy(SynToMulticastDstIp);
}




void TcpCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_TCP);
}

static Codec* ctor()
{
    return new TcpCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}



static const char* name = "tcp_decode";

static const CodecApi tcp_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    tcp_codec_ginit, // pinit
    tcp_codec_gterm, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
    NULL,
    NULL
};

const BaseApi* cd_tcp = &tcp_api.base;

