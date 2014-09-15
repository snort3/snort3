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
// cd_tcp.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "codecs/ip/checksum.h"
#include "codecs/sf_protocols.h"
#include "protocols/tcp.h"
#include "protocols/tcp_options.h"
#include "protocols/ipv6.h"
#include "protocols/packet.h"
#include "packet_io/active.h"
#include "codecs/codec_events.h"
#include "packet_io/sfdaq.h"
#include "parser/parse_ip.h"
#include "sfip/sf_ipvar.h"
#include "log/text_log.h"
#include "log/log_text.h"
#include "log/log.h"
#include "protocols/packet_manager.h"

#define CD_TCP_NAME "tcp"
#define CD_TCP_HELP "support for transmission control protocol"

using namespace tcp;

namespace
{

static const RuleMap tcp_rules[] =
{
    { DECODE_TCP_DGRAM_LT_TCPHDR, "(" CD_TCP_NAME ") TCP packet len is smaller than 20 bytes" },
    { DECODE_TCP_INVALID_OFFSET, "(" CD_TCP_NAME ") TCP Data Offset is less than 5" },
    { DECODE_TCP_LARGE_OFFSET, "(" CD_TCP_NAME ") TCP Header length exceeds packet length" },

    { DECODE_TCPOPT_BADLEN, "(" CD_TCP_NAME ") Tcp Options found with bad lengths" },
    { DECODE_TCPOPT_TRUNCATED, "(" CD_TCP_NAME ") Truncated Tcp Options" },
    { DECODE_TCPOPT_TTCP, "(" CD_TCP_NAME ") T/TCP Detected" },
    { DECODE_TCPOPT_OBSOLETE, "(" CD_TCP_NAME ") Obsolete TCP Options found" },
    { DECODE_TCPOPT_EXPERIMENTAL, "(" CD_TCP_NAME ") Experimental Tcp Options found" },
    { DECODE_TCPOPT_WSCALE_INVALID, "(" CD_TCP_NAME ") Tcp Window Scale Option found with length > 14" },
    { DECODE_TCP_XMAS, "(" CD_TCP_NAME ") XMAS Attack Detected" },
    { DECODE_TCP_NMAP_XMAS, "(" CD_TCP_NAME ") Nmap XMAS Attack Detected" },
    { DECODE_TCP_BAD_URP, "(" CD_TCP_NAME ") TCP urgent pointer exceeds payload length or no payload" },
    { DECODE_TCP_SYN_FIN, "(" CD_TCP_NAME ") TCP SYN with FIN" },
    { DECODE_TCP_SYN_RST, "(" CD_TCP_NAME ") TCP SYN with RST" },
    { DECODE_TCP_MUST_ACK, "(" CD_TCP_NAME ") TCP PDU missing ack for established session" },
    { DECODE_TCP_NO_SYN_ACK_RST, "(" CD_TCP_NAME ") TCP has no SYN, ACK, or RST" },
    { DECODE_TCP_SHAFT_SYNFLOOD, "(" CD_TCP_NAME ") DDOS shaft synflood" },
    { DECODE_TCP_PORT_ZERO, "(" CD_TCP_NAME ") BAD-TRAFFIC TCP port 0 traffic" },
    { DECODE_DOS_NAPTHA, "(decode) DOS NAPTHA Vulnerability Detected" },
    { DECODE_SYN_TO_MULTICAST, "(decode) Bad Traffic SYN to multicast address" },
    { 0, nullptr }
};

class TcpModule : public DecodeModule
{
public:
    TcpModule() : DecodeModule(CD_TCP_NAME, CD_TCP_HELP) {}

    const RuleMap* get_rules() const
    { return tcp_rules; }
};

class TcpCodec : public Codec
{
public:
    TcpCodec() : Codec(CD_TCP_NAME)
    {

    };
    virtual ~TcpCodec(){};


    virtual PROTO_ID get_proto_id() { return PROTO_TCP; };
    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual void log(TextLog* const, const uint8_t* /*raw_pkt*/,
                    const Packet* const);
    virtual bool decode(const RawData&, CodecData&, SnortData&);
    virtual bool encode(EncState*, Buffer* out, const uint8_t *raw_in);
    virtual bool update(Packet*, Layer*, uint32_t* len);
    virtual void format(EncodeFlags, const Packet* p, Packet* c, Layer*);
};

static sfip_var_t *SynToMulticastDstIp = NULL;

} // namespace



static int OptLenValidate(const tcp::TcpOption* const opt,
                            const uint8_t* const end,
                            const int expected_len);


static void DecodeTCPOptions(const uint8_t *, uint32_t, CodecData&);
static inline void TCPMiscTests(const SnortData& codec,
                                const tcp::TCPHdr* const tcph);

void TcpCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_TCP);
}

bool TcpCodec::decode(const RawData& raw, CodecData& codec, SnortData& snort)
{
    if(raw.len < tcp::TCP_HEADER_LEN)
    {
        codec_events::decoder_event(DECODE_TCP_DGRAM_LT_TCPHDR);
        return false;
    }

    /* lay TCP on top of the data cause there is enough of it! */
    const tcp::TCPHdr* tcph = reinterpret_cast<const tcp::TCPHdr*>(raw.data);
    const uint16_t tcph_len = tcph->hdr_len();

    if(tcph_len < tcp::TCP_HEADER_LEN)
    {
        codec_events::decoder_event(DECODE_TCP_INVALID_OFFSET);
        return false;
    }

    if(tcph_len > raw.len)
    {
        codec_events::decoder_event(DECODE_TCP_LARGE_OFFSET);
        return false;
    }

    /* Checksum code moved in front of the other decoder alerts.
       If it's a bad checksum (maybe due to encrypted ESP traffic), the other
       alerts could be false positives. */
    if (ScTcpChecksums())
    {
        uint16_t csum;
        if(snort.ip_api.is_ip4())
        {
            checksum::Pseudoheader ph;
            const ip::IP4Hdr* ip4h = snort.ip_api.get_ip4h();
            ph.sip = ip4h->get_src();
            ph.dip = ip4h->get_dst();
            /* setup the pseudo header for checksum calculation */
            ph.zero = 0;
            ph.protocol = ip4h->get_proto();
            ph.len = htons((uint16_t)raw.len);

            /* if we're being "stateless" we probably don't care about the TCP
             * checksum, but it's not bad to keep around for shits and giggles */
            /* calculate the checksum */
            csum = checksum::tcp_cksum((uint16_t *)(tcph), raw.len, &ph);

        }
        /* IPv6 traffic */
        else
        {
            checksum::Pseudoheader6 ph6;
            const ip::IP6Hdr* const ip6h = snort.ip_api.get_ip6h();
            COPY4(ph6.sip, ip6h->get_src()->u6_addr32);
            COPY4(ph6.dip, ip6h->get_dst()->u6_addr32);
            ph6.zero = 0;
            ph6.protocol = ip6h->get_next();
            ph6.len = htons((uint16_t)raw.len);


            csum = checksum::tcp_cksum((uint16_t *)(tcph), raw.len, &ph6);
        }

        if(csum)
        {
            /* Don't drop the packet if this is encapuslated in Teredo or ESP.
               Just get rid of the TCP header and stop decoding. */
            if (codec.codec_flags & CODEC_UNSURE_ENCAP)
                return false;


            snort.decode_flags |= DECODE_ERR_CKSUM_TCP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad TCP checksum\n",
                                    "0x%x versus 0x%x\n", csum,
                                    ntohs(tcph->th_sum)););


            if( ScInlineMode() && ScTcpChecksumDrops() )
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "Dropping bad packet (TCP checksum)\n"););
                Active_DropPacket();
            }
        }
    }

    if(tcph->are_flags_set(TH_FIN|TH_PUSH|TH_URG))
    {
        if(tcph->are_flags_set(TH_SYN|TH_ACK|TH_RST))
            codec_events::decoder_event(DECODE_TCP_XMAS);
        else
            codec_events::decoder_event(DECODE_TCP_NMAP_XMAS);

        // Allowing this packet for further processing
        // (in case there is a valid data inside it).
        /* return;*/
    }

    if(tcph->are_flags_set(TH_SYN))
    {
        /* check if only SYN is set */
        if( tcph->th_flags == TH_SYN )
        {
            if( tcph->th_seq == 6060842 )
            {
                if( snort.ip_api.id() == 413 )
                {
                    codec_events::decoder_event(DECODE_DOS_NAPTHA);
                }
            }
        }

        if( sfvar_ip_in(SynToMulticastDstIp, snort.ip_api.get_dst()) )
        {
            codec_events::decoder_event(DECODE_SYN_TO_MULTICAST);
        }
        if ( (tcph->th_flags & TH_RST) )
            codec_events::decoder_event(DECODE_TCP_SYN_RST);

        if ( (tcph->th_flags & TH_FIN) )
            codec_events::decoder_event(DECODE_TCP_SYN_FIN);
    }
    else
    {   // we already know there is no SYN
        if ( !(tcph->th_flags & (TH_ACK|TH_RST)) )
            codec_events::decoder_event(DECODE_TCP_NO_SYN_ACK_RST);
    }

    if ( (tcph->th_flags & (TH_FIN|TH_PUSH|TH_URG)) &&
        !(tcph->th_flags & TH_ACK) )
        codec_events::decoder_event(DECODE_TCP_MUST_ACK);


    /* if options are present, decode them */
    uint16_t tcp_opt_len = (uint16_t)(tcph->hdr_len() - tcp::TCP_HEADER_LEN);

    if(tcp_opt_len > 0)
        DecodeTCPOptions((uint8_t *) (raw.data + tcp::TCP_HEADER_LEN), tcp_opt_len, codec);


    int dsize = raw.len - tcph->hdr_len();
    if (dsize < 0)
        dsize = 0;

    if ( (tcph->th_flags & TH_URG) &&
        ((dsize == 0) || ntohs(tcph->th_urp) > dsize) )
        codec_events::decoder_event(DECODE_TCP_BAD_URP);

    // Now that we are returning true, set the tcp header
    codec.lyr_len = tcph_len;
    codec.proto_bits |= PROTO_BIT__TCP;
    snort.tcph = tcph;
    snort.sp = tcph->src_port();
    snort.dp = tcph->dst_port();

    TCPMiscTests(snort, tcph);

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
void DecodeTCPOptions(const uint8_t *start, uint32_t o_len, CodecData& codec)
{
    const uint8_t* const end_ptr = start + o_len; /* points to byte after last option */
    const tcp::TcpOption* opt = reinterpret_cast<const tcp::TcpOption*>(start);
    int code = 2;
    uint16_t tot_len = 0;
    bool done = false; /* have we reached TCPOPT_EOL yet?*/
    bool experimental_option_found = false;      /* are all options RFC compliant? */
    bool obsolete_option_found = false;



    /* Here's what we're doing so that when we find out what these
     * other buggers of TCP option codes are, we can do something
     * useful
     *
     * 1) get option code
     * 2) check for enough space for current option code
     * 4) increment option code ptr
     *
     * TCP_OPTLENMAX = 40 because of
     *        (((2^4) - 1) * 4  - tcp::TCP_HEADER_LEN
     *
     */

    while((tot_len < o_len) && !done)
    {
        switch(opt->code)
        {
        case tcp::TcpOptCode::EOL:
            done = true; /* fall through to the NOP case */
            codec.invalid_bytes = o_len - tot_len;
        case tcp::TcpOptCode::NOP:
            code = 0;
            break;

        case tcp::TcpOptCode::MAXSEG:
            code = OptLenValidate(opt, end_ptr, TCPOLEN_MAXSEG);
            break;

        case tcp::TcpOptCode::SACKOK:
            code = OptLenValidate(opt, end_ptr, TCPOLEN_SACKOK);
            break;

        case tcp::TcpOptCode::WSCALE:
            code = OptLenValidate(opt, end_ptr, TCPOLEN_WSCALE);
            if (code == 0)
            {
                if (((uint16_t) opt->data[0] > 14))
                {
                    /* LOG INVALID WINDOWSCALE alert */
                    codec_events::decoder_event(DECODE_TCPOPT_WSCALE_INVALID);
                }
            }
            break;

        case tcp::TcpOptCode::ECHO: /* both use the same lengths */
        case tcp::TcpOptCode::ECHOREPLY:
            obsolete_option_found = true;
            code = OptLenValidate(opt, end_ptr, TCPOLEN_ECHO);
            break;

        case tcp::TcpOptCode::MD5SIG:
            /* RFC 5925 obsoletes this option (see below) */
            obsolete_option_found = 1;
            code = OptLenValidate(opt, end_ptr, TCPOLEN_MD5SIG);
            break;

        case tcp::TcpOptCode::AUTH:
            code = OptLenValidate(opt, end_ptr, -1);

            /* Has to have at least 4 bytes - see RFC 5925, Section 2.2 */
            if (code >= 0 && opt->len < 4)
                code = tcp::OPT_BADLEN;
            break;

        case tcp::TcpOptCode::SACK:
            code = OptLenValidate(opt, end_ptr, -1);

            if((code >= 0) && (opt->len < 2))
                code = tcp::OPT_BADLEN;
            break;

        case tcp::TcpOptCode::CC_ECHO:
            codec_events::decoder_event(DECODE_TCPOPT_TTCP);
            /* fall through */
        case tcp::TcpOptCode::CC:  /* all 3 use the same lengths / T/TCP */
        case tcp::TcpOptCode::CC_NEW:
            code = OptLenValidate(opt, end_ptr, TCPOLEN_CC);
            break;

        case tcp::TcpOptCode::TRAILER_CSUM:
            experimental_option_found = true;
            code = OptLenValidate(opt, end_ptr, TCPOLEN_TRAILER_CSUM);
            break;

        case tcp::TcpOptCode::TIMESTAMP:
            code = OptLenValidate(opt, end_ptr, TCPOLEN_TIMESTAMP);
            break;

        case tcp::TcpOptCode::SKEETER:
        case tcp::TcpOptCode::BUBBA:
        case tcp::TcpOptCode::UNASSIGNED:
            obsolete_option_found = true;
            code = OptLenValidate(opt, end_ptr, -1);
            break;

        case tcp::TcpOptCode::SCPS:
        case tcp::TcpOptCode::SELNEGACK:
        case tcp::TcpOptCode::RECORDBOUND:
        case tcp::TcpOptCode::CORRUPTION:
        case tcp::TcpOptCode::PARTIAL_PERM:
        case tcp::TcpOptCode::PARTIAL_SVC:
        case tcp::TcpOptCode::ALTCSUM:
        case tcp::TcpOptCode::SNAP:
        default:
            experimental_option_found = true;
            code = OptLenValidate(opt, end_ptr, -1);
            break;
        }

        if(code < 0)
        {
            if(code == tcp::OPT_BADLEN)
            {
                codec_events::decoder_event(DECODE_TCPOPT_BADLEN);
            }
            else if(code == tcp::OPT_TRUNC)
            {
                codec_events::decoder_event(DECODE_TCPOPT_TRUNCATED);
            }

            /* set the option count to the number of valid
             * options found before this bad one
             * some implementations (BSD and Linux) ignore
             * the bad ones, but accept the good ones */
            codec.invalid_bytes = o_len - tot_len;

            return;
        }

        tot_len += ((uint8_t)opt->code <= 1) ? 1 : opt->len;
        opt = &(opt->next());
    }

    if (experimental_option_found)
    {
        codec_events::decoder_event(DECODE_TCPOPT_EXPERIMENTAL);
    }
    else if (obsolete_option_found)
    {
        codec_events::decoder_event(DECODE_TCPOPT_OBSOLETE);
    }

    return;
}


static int OptLenValidate(const tcp::TcpOption* const opt,
                            const uint8_t* const end,
                            const int expected_len)
{
    // case for pointer arithmetic
    const uint8_t* const opt_ptr = reinterpret_cast<const uint8_t* const>(opt);


    if(expected_len > 1)
    {
        /* not enough data to read in a perfect world */
        if((opt_ptr + expected_len) > end)
            return tcp::OPT_TRUNC;

        if(opt->len != expected_len)
            return tcp::OPT_BADLEN;
    }
    else /* expected_len < 0 (i.e. variable length) */
    {
        /* RFC sez that we MUST have atleast this much data */
        if(opt->len < 2)
            return tcp::OPT_BADLEN;

        /* not enough data to read in a perfect world */
        if((opt_ptr + opt->len) > end)
            return tcp::OPT_TRUNC;
    }

    return 0;
}


/* TCP-layer decoder alerts */
static inline void TCPMiscTests(const SnortData& snort, const tcp::TCPHdr* const tcph)
{
    if ( ((tcph->th_flags & TH_NORESERVED) == TH_SYN ) &&
         (tcph->seq() == 674711609) )
        codec_events::decoder_event(DECODE_TCP_SHAFT_SYNFLOOD);

    if (snort.sp == 0 || snort.dp == 0)
        codec_events::decoder_event(DECODE_TCP_PORT_ZERO);

}

/******************************************************************
 ************************  L O G G E R   **************************
 ******************************************************************/


void TcpCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
                    const Packet* const p)
{
    char tcpFlags[9];

    const tcp::TCPHdr* const tcph = reinterpret_cast<const tcp::TCPHdr*>(raw_pkt);

    /* print TCP flags */
    CreateTCPFlagString(tcph, tcpFlags);
    TextLog_Puts(text_log, tcpFlags); /* We don't care about the NULL */

    /* print other TCP info */
    TextLog_Print(text_log, "  SrcPort:%u  DstPort:%u\n\tSeq: 0x%lX  Ack: 0x%lX  "
            "Win: 0x%X  TcpLen: %d",ntohs(tcph->th_sport),
            ntohs(tcph->th_dport), (u_long) ntohl(tcph->th_seq),
            (u_long) ntohl(tcph->th_ack),
            ntohs(tcph->th_win), tcph->off() << 2);

    if((tcph->th_flags & TH_URG) != 0)
        TextLog_Print(text_log, "UrgPtr: 0x%X", (uint16_t) ntohs(tcph->th_urp));


    /* dump the TCP options */
    if(tcph->has_options())
    {
        TextLog_Puts(text_log, "\n\t");
        LogTcpOptions(text_log, p);
    }
}


/******************************************************************
 ************************* E N C O D E R  *************************
 ******************************************************************/

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

bool TcpCodec::encode (EncState* enc, Buffer* out, const uint8_t* raw_in)
{
    int ctl;
    const tcp::TCPHdr* hi = reinterpret_cast<const tcp::TCPHdr*>(raw_in);
    bool attach_payload = (enc->type == EncodeType::ENC_TCP_FIN || 
        enc->type == EncodeType::ENC_TCP_PUSH);

    // working our way backwards throught he packet. First, attach a payload
    if ( attach_payload && enc->payLoad && enc->payLen > 0 )
    {
        if (!update_buffer(out, enc->payLen))
            return false;
        memcpy(out->base, enc->payLoad, enc->payLen);
    }

    if (!update_buffer(out, hi->hdr_len()))
        return false;

    tcp::TCPHdr* ho = reinterpret_cast<tcp::TCPHdr*>(out->base);
    ctl = (hi->th_flags & TH_SYN) ? 1 : 0;

    if ( forward(enc->flags) )
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
    ho->set_offset(tcp::TCP_HEADER_LEN >> 2);
    ho->th_win = ho->th_urp = 0;

    if ( attach_payload )
    {
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
    const ip::IpApi* const ip_api = &enc->p->ptrs.ip_api;

    if (ip_api->is_ip4()) {
        checksum::Pseudoheader ps;
        int len = buff_diff(out, (uint8_t*)ho);

        const IP4Hdr* const ip4h = ip_api->get_ip4h();
        ps.sip = ip4h->get_src();
        ps.dip = ip4h->get_dst();
        ps.zero = 0;
        ps.protocol = IPPROTO_TCP;
        ps.len = htons((uint16_t)len);
        ho->th_sum = checksum::tcp_cksum((uint16_t *)ho, len, &ps);
    }
    else
    {
        checksum::Pseudoheader6 ps6;
        int len = buff_diff(out, (uint8_t*) ho);

        const ip::IP6Hdr* const ip6h = ip_api->get_ip6h();
        memcpy(ps6.sip, ip6h->get_src()->u6_addr8, sizeof(ps6.sip));
        memcpy(ps6.dip, ip6h->get_dst()->u6_addr8, sizeof(ps6.dip));
        ps6.zero = 0;
        ps6.protocol = IPPROTO_TCP;
        ps6.len = htons((uint16_t)len);
        ho->th_sum = checksum::tcp_cksum((uint16_t *)ho, len, &ps6);
    }

    return true;
}

bool TcpCodec::update(Packet* p, Layer* lyr, uint32_t* len)
{
    tcp::TCPHdr* h = reinterpret_cast<tcp::TCPHdr*>(const_cast<uint8_t*>(lyr->start));

    *len += h->hdr_len() + p->dsize;

    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) )
    {
        h->th_sum = 0;

        if (p->ptrs.ip_api.is_ip4())
        {
            checksum::Pseudoheader ps;
            const ip::IP4Hdr* const ip4h = p->ptrs.ip_api.get_ip4h();
            ps.sip = ip4h->get_src();
            ps.dip = ip4h->get_dst();;
            ps.zero = 0;
            ps.protocol = IPPROTO_TCP;
            ps.len = htons((uint16_t)*len);
            h->th_sum = checksum::tcp_cksum((uint16_t *)h, *len, &ps);
        }
        else
        {
            checksum::Pseudoheader6 ps6;
            const ip::IP6Hdr* const ip6h = p->ptrs.ip_api.get_ip6h();
            memcpy(ps6.sip, ip6h->get_src()->u6_addr32, sizeof(ps6.sip));
            memcpy(ps6.dip, ip6h->get_dst()->u6_addr32, sizeof(ps6.dip));
            ps6.zero = 0;
            ps6.protocol = IPPROTO_TCP;
            ps6.len = htons((uint16_t)*len);
            h->th_sum = checksum::tcp_cksum((uint16_t *)h, *len, &ps6);
        }
    }

    return true;
}

void TcpCodec::format(EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    tcp::TCPHdr* ch = (tcp::TCPHdr*)lyr->start;
    c->ptrs.tcph = ch;

    if ( reverse(f) )
    {
        int i = lyr - c->layers;
        tcp::TCPHdr* ph = (tcp::TCPHdr*)p->layers[i].start;

        ch->th_sport = ph->th_dport;
        ch->th_dport = ph->th_sport;
    }
    c->ptrs.sp = ch->src_port();
    c->ptrs.dp = ch->dst_port();
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new TcpModule; }

static void mod_dtor(Module* m)
{ delete m; }

/*
 * Static api functions.  there are NOT part of the TCPCodec class,
 * but provide global initializers and/or destructors to the class
 */

static void tcp_codec_ginit()
{
    SynToMulticastDstIp = sfip_var_from_string(
        "[232.0.0.0/8,233.0.0.0/8,239.0.0.0/8]");

    if( SynToMulticastDstIp == NULL )
        FatalError("Could not initialize SynToMulticastDstIp\n");

}

static void tcp_codec_gterm()
{
    if( SynToMulticastDstIp )
        sfvar_free(SynToMulticastDstIp);
}

static Codec* ctor(Module*)
{ return new TcpCodec(); }

static void dtor(Codec *cd)
{ delete cd; }

static const CodecApi tcp_api =
{
    {
        PT_CODEC,
        CD_TCP_NAME,
        CD_TCP_HELP,
        CDAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor,
    },
    tcp_codec_ginit, // pinit
    tcp_codec_gterm, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    dtor, // dtor
};

const BaseApi* cd_tcp = &tcp_api.base;
