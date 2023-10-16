//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// cd_tcp.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <daq.h>

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/log.h"
#include "log/log_text.h"
#include "main/snort_config.h"
#include "parser/parse_ip.h"
#include "protocols/tcp.h"
#include "protocols/tcp_options.h"
#include "sfip/sf_ipvar.h"
#include "stream/stream.h"
#include "utils/util.h"

#include "checksum.h"

using namespace snort;

#define CD_TCP_NAME "tcp"
#define CD_TCP_HELP "support for transmission control protocol"

#ifdef WORDS_BIGENDIAN
    const uint32_t naptha_seq = 0x005c7b2a;
    const uint16_t naptha_id = 0x019d;
#else
    const uint32_t naptha_seq = 0x2a7b5c00;
    const uint16_t naptha_id = 0x9d01;
#endif

using namespace tcp;

namespace
{
const PegInfo pegs[]
{
    { CountType::SUM, "bad_tcp4_checksum", "nonzero tcp over ip checksums" },
    { CountType::SUM, "bad_tcp6_checksum", "nonzero tcp over ipv6 checksums" },
    { CountType::SUM, "checksum_bypassed", "checksum calculations bypassed" },
    { CountType::END, nullptr, nullptr }
};

struct Stats
{
    PegCount bad_ip4_cksum;
    PegCount bad_ip6_cksum;
    PegCount cksum_bypassed;
};

static THREAD_LOCAL Stats stats;

static const RuleMap tcp_rules[] =
{
    { DECODE_TCP_DGRAM_LT_TCPHDR, "TCP packet length is smaller than 20 bytes" },
    { DECODE_TCP_INVALID_OFFSET, "TCP data offset is less than 5" },
    { DECODE_TCP_LARGE_OFFSET, "TCP header length exceeds packet length" },
    { DECODE_TCPOPT_BADLEN, "TCP options found with bad lengths" },
    { DECODE_TCPOPT_TRUNCATED, "truncated TCP options" },
    { DECODE_TCPOPT_TTCP, "T/TCP detected" },
    { DECODE_TCPOPT_OBSOLETE, "obsolete TCP options found" },
    { DECODE_TCPOPT_EXPERIMENTAL, "experimental TCP options found" },
    { DECODE_TCPOPT_WSCALE_INVALID, "TCP window scale option found with length > 14" },
    { DECODE_TCP_XMAS, "XMAS attack detected" },
    { DECODE_TCP_NMAP_XMAS, "Nmap XMAS attack detected" },
    { DECODE_TCP_BAD_URP, "TCP urgent pointer exceeds payload length or no payload" },
    { DECODE_TCP_SYN_FIN, "TCP SYN with FIN" },
    { DECODE_TCP_SYN_RST, "TCP SYN with RST" },
    { DECODE_TCP_MUST_ACK, "TCP PDU missing ack for established session" },
    { DECODE_TCP_NO_SYN_ACK_RST, "TCP has no SYN, ACK, or RST" },
    { DECODE_TCP_SHAFT_SYNFLOOD, "DDOS shaft SYN flood" },
    { DECODE_TCP_PORT_ZERO, "TCP port 0 traffic" },
    { DECODE_DOS_NAPTHA, "DOS NAPTHA vulnerability detected" },
    { DECODE_SYN_TO_MULTICAST, "SYN to multicast address" },
    { 0, nullptr }
};

class TcpModule : public BaseCodecModule
{
public:
    TcpModule() : BaseCodecModule(CD_TCP_NAME, CD_TCP_HELP) { }

    const RuleMap* get_rules() const override
    { return tcp_rules; }

    const PegInfo* get_pegs() const override
    { return pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&stats; }
};

class TcpCodec : public Codec
{
public:
    TcpCodec() : Codec(CD_TCP_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;

    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&, Flow*) override;

    void update(const ip::IpApi&, const EncodeFlags, uint8_t* raw_pkt,
        uint16_t lyr_len, uint32_t& updated_len) override;

    void format(bool reverse, uint8_t* raw_pkt, DecodeData& snort) override;

private:
    bool valid_checksum_from_daq(const RawData&);
    bool valid_checksum4(const RawData&, DecodeData&);
    bool valid_checksum6(const RawData&, const CodecData&, DecodeData&);

    int validate_option(const tcp::TcpOption* const opt,
        const uint8_t* const end, const int expected_len);
    int validate_option(const tcp::TcpOption* const opt,
        const uint8_t* const end);

    void decode_options(const uint8_t*, uint32_t, CodecData&, DecodeData&);

    void flag_tests(const tcp::TCPHdr* const tcph,
        const DecodeData& snort, const CodecData& codec);
};

static sfip_var_t* SynToMulticastDstIp = nullptr;
} // namespace

void TcpCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.emplace_back(ProtocolId::TCP);
}

inline bool TcpCodec::valid_checksum_from_daq(const RawData& raw)
{
    const DAQ_PktDecodeData_t* pdd =
        (const DAQ_PktDecodeData_t*) daq_msg_get_meta(raw.daq_msg, DAQ_PKT_META_DECODE_DATA);
    if (!pdd || !pdd->flags.bits.l4_checksum || !pdd->flags.bits.tcp || !pdd->flags.bits.l4)
        return false;
    // Sanity check to make sure we're talking about the same thing if offset is available
    if (pdd->l4_offset != DAQ_PKT_DECODE_OFFSET_INVALID)
    {
        const uint8_t* data = daq_msg_get_data(raw.daq_msg);
        if (raw.data - data != pdd->l4_offset)
            return false;
    }
    stats.cksum_bypassed++;
    return true;
}

bool TcpCodec::valid_checksum4(const RawData& raw, DecodeData& snort)
{
    const ip::IP4Hdr* ip4h = snort.ip_api.get_ip4h();

    checksum::Pseudoheader ph;
    ph.hdr.sip = ip4h->get_src();
    ph.hdr.dip = ip4h->get_dst();
    ph.hdr.zero = 0;
    ph.hdr.protocol = ip4h->proto();
    ph.hdr.len = htons((uint16_t) raw.len);

    return (checksum::tcp_cksum((const uint16_t*) raw.data, raw.len, ph) == 0);
}

bool TcpCodec::valid_checksum6(const RawData& raw, const CodecData& codec, DecodeData& snort)
{
    const ip::IP6Hdr* const ip6h = snort.ip_api.get_ip6h();

    checksum::Pseudoheader6 ph6;
    COPY4(ph6.hdr.sip, ip6h->get_src()->u6_addr32);
    COPY4(ph6.hdr.dip, ip6h->get_dst()->u6_addr32);
    ph6.hdr.zero = 0;
    ph6.hdr.protocol = codec.ip6_csum_proto;
    ph6.hdr.len = htons((uint16_t) raw.len);

    return (checksum::tcp_cksum((const uint16_t*) raw.data, raw.len, ph6) == 0);
}

bool TcpCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    if (raw.len < tcp::TCP_MIN_HEADER_LEN)
    {
        codec_event(codec, DECODE_TCP_DGRAM_LT_TCPHDR);
        return false;
    }

    const tcp::TCPHdr* tcph = reinterpret_cast<const tcp::TCPHdr*>(raw.data);
    const uint16_t tcph_len = tcph->hlen();

    if (tcph_len < tcp::TCP_MIN_HEADER_LEN)
    {
        codec_event(codec, DECODE_TCP_INVALID_OFFSET);
        return false;
    }

    if (tcph_len > raw.len)
    {
        codec_event(codec, DECODE_TCP_LARGE_OFFSET);
        return false;
    }

    if (snort::get_network_policy()->tcp_checksums() && !valid_checksum_from_daq(raw))
    {
        PegCount* bad_cksum_cnt;
        bool valid;

        if (snort.ip_api.is_ip4())
        {
            valid = valid_checksum4(raw, snort);
            bad_cksum_cnt = &stats.bad_ip4_cksum;
        }
        else
        {
            valid = valid_checksum6(raw, codec, snort);
            bad_cksum_cnt = &stats.bad_ip6_cksum;
        }

        if (!valid)
        {
            if (!(codec.codec_flags & CODEC_UNSURE_ENCAP))
            {
                (*bad_cksum_cnt)++;
                snort.decode_flags |= DECODE_ERR_CKSUM_TCP;
            }
            return false;
        }
    }

    flag_tests(tcph, snort, codec);

    /* if options are present, decode them */
    uint16_t tcp_opt_len = (uint16_t)(tcph->hlen() - tcp::TCP_MIN_HEADER_LEN);

    if (tcp_opt_len > 0)
    {
        const uint8_t* opts = (const uint8_t*)(raw.data + tcp::TCP_MIN_HEADER_LEN);
        decode_options(opts, tcp_opt_len, codec, snort);
    }
    int dsize = raw.len - tcph->hlen();

    if (dsize < 0)
        dsize = 0;

    if ( (tcph->th_flags & TH_URG) && ((dsize == 0) || tcph->urp() > dsize) )
        codec_event(codec, DECODE_TCP_BAD_URP);

    // Now that we are returning true, set the tcp header
    codec.lyr_len = tcph_len - codec.invalid_bytes;
    codec.proto_bits |= PROTO_BIT__TCP;

    snort.set_pkt_type(PktType::TCP);
    snort.tcph = tcph;

    const DAQ_NAPTInfo_t* napti = (const DAQ_NAPTInfo_t*) daq_msg_get_meta(raw.daq_msg, DAQ_PKT_META_NAPT_INFO);
    if (napti && codec.ip_layer_cnt == napti->ip_layer)
    {
        snort.sp = ntohs(napti->src_port);
        snort.dp = ntohs(napti->dst_port);
    }
    else
    {
        snort.sp = tcph->src_port();
        snort.dp = tcph->dst_port();
    }

    if (snort.sp == 0 || snort.dp == 0)
        codec_event(codec, DECODE_TCP_PORT_ZERO);

    return true;
}

/*
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
 */
void TcpCodec::decode_options(
    const uint8_t* start, uint32_t o_len, CodecData& codec, DecodeData& snort)
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
     *        (((2^4) - 1) * 4  - tcp::TCP_MIN_HEADER_LEN
     *
     */

    while ((tot_len < o_len) && !done)
    {
        switch (opt->code)
        {
        case tcp::TcpOptCode::EOL:
            done = true;
            codec.invalid_bytes = o_len - tot_len;
            /* fallthrough */
        case tcp::TcpOptCode::NOP:
            code = 0;
            break;

        case tcp::TcpOptCode::MAXSEG:
            code = validate_option(opt, end_ptr, TCPOLEN_MAXSEG);
            if (code == 0)
                snort.decode_flags |= DECODE_TCP_MSS;
            break;

        case tcp::TcpOptCode::SACKOK:
            code = validate_option(opt, end_ptr, TCPOLEN_SACKOK);
            break;

        case tcp::TcpOptCode::WSCALE:
            code = validate_option(opt, end_ptr, TCPOLEN_WSCALE);
            if (code == 0)
            {
                if (((uint16_t)opt->data[0] > 14))
                {
                    /* LOG INVALID WINDOWSCALE alert */
                    codec_event(codec, DECODE_TCPOPT_WSCALE_INVALID);
                }
                snort.decode_flags |= DECODE_TCP_WS;
            }
            break;

        case tcp::TcpOptCode::ECHO: /* both use the same lengths */
        case tcp::TcpOptCode::ECHOREPLY:
            obsolete_option_found = true;
            code = validate_option(opt, end_ptr, TCPOLEN_ECHO);
            break;

        case tcp::TcpOptCode::MD5SIG:
            /* RFC 5925 obsoletes this option (see below) */
            obsolete_option_found = true;
            code = validate_option(opt, end_ptr, TCPOLEN_MD5SIG);
            break;

        case tcp::TcpOptCode::AUTH:
            code = validate_option(opt, end_ptr);

            /* Has to have at least 4 bytes - see RFC 5925, Section 2.2 */
            if (code >= 0 && opt->len < 4)
                code = tcp::OPT_BADLEN;
            break;

        case tcp::TcpOptCode::SACK:
            code = validate_option(opt, end_ptr);

            if ((code >= 0) && (opt->len < 2))
                code = tcp::OPT_BADLEN;
            break;

        case tcp::TcpOptCode::CC_ECHO:
            codec_event(codec, DECODE_TCPOPT_TTCP);
        /* fall through */
        case tcp::TcpOptCode::CC:  /* all 3 use the same lengths / T/TCP */
        case tcp::TcpOptCode::CC_NEW:
            code = validate_option(opt, end_ptr, TCPOLEN_CC);
            break;

        case tcp::TcpOptCode::TRAILER_CSUM:
            experimental_option_found = true;
            code = validate_option(opt, end_ptr, TCPOLEN_TRAILER_CSUM);
            break;

        case tcp::TcpOptCode::TIMESTAMP:
            code = validate_option(opt, end_ptr, TCPOLEN_TIMESTAMP);
            if (code == 0)
                snort.decode_flags |= DECODE_TCP_TS;
            break;

        case tcp::TcpOptCode::SKEETER:
        case tcp::TcpOptCode::BUBBA:
        case tcp::TcpOptCode::UNASSIGNED:
            obsolete_option_found = true;
            code = validate_option(opt, end_ptr);
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
            code = validate_option(opt, end_ptr);
            break;
        }

        if (code < 0)
        {
            if (code == tcp::OPT_BADLEN)
            {
                codec_event(codec, DECODE_TCPOPT_BADLEN);
            }
            else if (code == tcp::OPT_TRUNC)
            {
                codec_event(codec, DECODE_TCPOPT_TRUNCATED);
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
        codec_event(codec, DECODE_TCPOPT_EXPERIMENTAL);

    else if (obsolete_option_found)
        codec_event(codec, DECODE_TCPOPT_OBSOLETE);
}

int TcpCodec::validate_option(const tcp::TcpOption* const opt,
    const uint8_t* const end, const int expected_len)
{
    const uint8_t* const opt_ptr = reinterpret_cast<const uint8_t*>(opt);

    assert(expected_len > 1);

    /* not enough data to read in a perfect world */
    if ((opt_ptr + expected_len) > end)
        return tcp::OPT_TRUNC;

    if (opt->len != expected_len)
        return tcp::OPT_BADLEN;

    return 0;
}

int TcpCodec::validate_option(const tcp::TcpOption* const opt, const uint8_t* const end)
{
    const uint8_t* const opt_ptr = reinterpret_cast<const uint8_t*>(opt);

    /* not enough data to read in a perfect world */
    if ((opt_ptr + 2) > end or (opt_ptr + opt->len) > end)
        return tcp::OPT_TRUNC;

    /* RFC says that we MUST have at least this much data */
    if (opt->len < 2)
        return tcp::OPT_BADLEN;

    return 0;
}

void TcpCodec::flag_tests(const tcp::TCPHdr* const tcph,
    const DecodeData& snort, const CodecData& codec)
{
    if (tcph->are_flags_set(TH_FIN|TH_PUSH|TH_URG))
    {
        if (tcph->are_flags_set(TH_SYN|TH_ACK|TH_RST))
            codec_event(codec, DECODE_TCP_XMAS);
        else
            codec_event(codec, DECODE_TCP_NMAP_XMAS);
    }

    if (tcph->are_flags_set(TH_SYN))
    {
        if ( tcph->th_flags == TH_SYN )
        {
            if ((tcph->th_seq == naptha_seq) and snort.ip_api.is_ip4() and
                (snort.ip_api.get_ip4h()->ip_id  == naptha_id))
            {
                codec_event(codec, DECODE_DOS_NAPTHA);
            }
        }

        if ( codec.conf->is_address_anomaly_check_enabled() )
        {
            if ( sfvar_ip_in(SynToMulticastDstIp, snort.ip_api.get_dst()) )
                codec_event(codec, DECODE_SYN_TO_MULTICAST);
        }

        if ( (tcph->th_flags & TH_RST) )
            codec_event(codec, DECODE_TCP_SYN_RST);

        if ( (tcph->th_flags & TH_FIN) )
            codec_event(codec, DECODE_TCP_SYN_FIN);

        if ( ((tcph->th_flags & TH_NORESERVED) == TH_SYN ) && (tcph->seq() == 674711609) )
            codec_event(codec, DECODE_TCP_SHAFT_SYNFLOOD);
    }
    else
    {   // we already know there is no SYN
        if ( !(tcph->th_flags & (TH_ACK|TH_RST)) )
            codec_event(codec, DECODE_TCP_NO_SYN_ACK_RST);
    }

    if ( (tcph->th_flags & (TH_FIN|TH_PUSH|TH_URG)) &&
        !(tcph->th_flags & TH_ACK) )
        codec_event(codec, DECODE_TCP_MUST_ACK);

}

/******************************************************************
 ************************  L O G G E R   **************************
 ******************************************************************/

void TcpCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t lyr_len)
{
    char tcpFlags[9];

    const tcp::TCPHdr* const tcph = reinterpret_cast<const tcp::TCPHdr*>(raw_pkt);

    /* print TCP flags */
    CreateTCPFlagString(tcph, tcpFlags);
    TextLog_Puts(text_log, tcpFlags); /* We don't care about the null */

    /* print other TCP info */
    TextLog_Print(text_log, "  SrcPort:%u  DstPort:%u\n\tSeq: 0x%lX  Ack: 0x%lX  "
        "Win: 0x%X  TcpLen: %d",ntohs(tcph->th_sport),
        ntohs(tcph->th_dport), (u_long)ntohl(tcph->th_seq),
        (u_long)ntohl(tcph->th_ack),
        ntohs(tcph->th_win), tcph->off());

    if ((tcph->th_flags & TH_URG) != 0)
        TextLog_Print(text_log, "UrgPtr: 0x%X", tcph->urp());

    /* dump the TCP options */
    if (tcph->has_options())
    {
        TextLog_Puts(text_log, "\n\t");
        LogTcpOptions(text_log, tcph, lyr_len);
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

bool TcpCodec::encode(const uint8_t* const raw_in, const uint16_t /*raw_len*/,
    EncState& enc, Buffer& buf, Flow* flow)
{
    const tcp::TCPHdr* const hi = reinterpret_cast<const tcp::TCPHdr*>(raw_in);

    if (!buf.allocate(tcp::TCP_MIN_HEADER_LEN))
        return false;

    tcp::TCPHdr* tcph_out = reinterpret_cast<tcp::TCPHdr*>(buf.data());
    const int ctl = (hi->th_flags & TH_SYN) ? 1 : 0;

    if ( enc.forward() )
    {
        tcph_out->th_sport = hi->th_sport;
        tcph_out->th_dport = hi->th_dport;

        // th_seq depends on whether the data passes or drops
        if (enc.flags & ENC_FLAG_INLINE)
        {
            uint32_t seq = 0;

            if(Stream::get_held_pkt_seq(flow, seq))
                tcph_out->th_seq = htonl(seq);
            else
                tcph_out->th_seq = hi->th_seq;
        }
        else
            tcph_out->th_seq = htonl(ntohl(hi->th_seq) + enc.dsize + ctl);

        tcph_out->th_ack = hi->th_ack;
    }
    else
    {
        tcph_out->th_sport = hi->th_dport;
        tcph_out->th_dport = hi->th_sport;

        tcph_out->th_seq = hi->th_ack;
        tcph_out->th_ack = htonl(ntohl(hi->th_seq) + enc.dsize + ctl);
    }

    if ( enc.flags & ENC_FLAG_SEQ )
    {
        uint32_t seq = ntohl(tcph_out->th_seq);
        seq += (enc.flags & ENC_FLAG_VAL);
        tcph_out->th_seq = htonl(seq);
    }

    tcph_out->th_offx2 = 0;
    tcph_out->set_offset(tcp::TCP_MIN_HEADER_LEN >> 2);
    tcph_out->th_win = 0;
    tcph_out->th_urp = 0;

    if ( (enc.flags & (ENC_FLAG_PSH | ENC_FLAG_FIN)) )
    {
        tcph_out->th_flags = TH_ACK;
        if ( enc.flags & ENC_FLAG_PSH )
        {
            tcph_out->th_flags |= TH_PUSH;
            tcph_out->th_win = htons(65535);
        }
        else
        {
            tcph_out->th_flags |= TH_FIN;
        }
    }
    else
    {
        tcph_out->th_flags = TH_RST | TH_ACK;
    }

    // in case of ip6 extension headers, this gets next correct
    enc.next_proto = IpProtocol::TCP;
    tcph_out->th_sum = 0;
    const ip::IpApi& ip_api = enc.ip_api;

    if (ip_api.is_ip4())
    {
        checksum::Pseudoheader ps;
        int len = buf.size();

        const ip::IP4Hdr* const ip4h = ip_api.get_ip4h();
        ps.hdr.sip = ip4h->get_src();
        ps.hdr.dip = ip4h->get_dst();
        ps.hdr.zero = 0;
        ps.hdr.protocol = IpProtocol::TCP;
        ps.hdr.len = htons((uint16_t)len);
        tcph_out->th_sum = checksum::tcp_cksum((uint16_t*)tcph_out, len, ps);
    }
    else if (ip_api.is_ip6())
    {
        checksum::Pseudoheader6 ps6;
        int len = buf.size();

        const ip::IP6Hdr* const ip6h = ip_api.get_ip6h();
        memcpy(&ps6.hdr.sip, ip6h->get_src()->u6_addr8, sizeof(ps6.hdr.sip));
        memcpy(&ps6.hdr.dip, ip6h->get_dst()->u6_addr8, sizeof(ps6.hdr.dip));
        ps6.hdr.zero = 0;
        ps6.hdr.protocol = IpProtocol::TCP;
        ps6.hdr.len = htons((uint16_t)len);
        tcph_out->th_sum = checksum::tcp_cksum((uint16_t*)tcph_out, len, ps6);
    }

    return true;
}

void TcpCodec::update(const ip::IpApi& api, const EncodeFlags flags, uint8_t* raw_pkt,
    uint16_t /*lyr_len*/, uint32_t& updated_len)
{
    tcp::TCPHdr* const h = reinterpret_cast<tcp::TCPHdr*>(raw_pkt);

    updated_len += h->hlen();

    if ( !(flags & UPD_COOKED) || (flags & UPD_REBUILT_FRAG) )
    {
        h->th_sum = 0;

        if ( api.is_ip4() )
        {
            checksum::Pseudoheader ps;
            const ip::IP4Hdr* const ip4h = api.get_ip4h();
            ps.hdr.sip = ip4h->get_src();
            ps.hdr.dip = ip4h->get_dst();
            ps.hdr.zero = 0;
            ps.hdr.protocol = IpProtocol::TCP;
            ps.hdr.len = htons((uint16_t)updated_len);
            h->th_sum = checksum::tcp_cksum((uint16_t*)h, updated_len, ps);
        }
        else
        {
            checksum::Pseudoheader6 ps6;
            const ip::IP6Hdr* const ip6h = api.get_ip6h();
            memcpy(ps6.hdr.sip, ip6h->get_src()->u6_addr32, sizeof(ps6.hdr.sip));
            memcpy(ps6.hdr.dip, ip6h->get_dst()->u6_addr32, sizeof(ps6.hdr.dip));
            ps6.hdr.zero = 0;
            ps6.hdr.protocol = IpProtocol::TCP;
            ps6.hdr.len = htons((uint16_t)updated_len);
            h->th_sum = checksum::tcp_cksum((uint16_t*)h, updated_len, ps6);
        }
    }
}

void TcpCodec::format(bool reverse, uint8_t* raw_pkt, DecodeData& snort)
{
    tcp::TCPHdr* tcph = reinterpret_cast<tcp::TCPHdr*>(raw_pkt);

    if ( reverse )
    {
        uint16_t tmp_port = tcph->th_sport;
        tcph->th_sport = tcph->th_dport;
        tcph->th_dport = tmp_port;
    }

    snort.tcph = tcph;
    snort.sp = tcph->src_port();
    snort.dp = tcph->dst_port();
    snort.set_pkt_type(PktType::TCP);
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
    // Multicast addresses pursuant to RFC 5771
    SynToMulticastDstIp = sfip_var_from_string("[224.0.0.0/4]", "tcp");
    assert(SynToMulticastDstIp);
}

static void tcp_codec_gterm()
{
    if ( SynToMulticastDstIp )
        sfvar_free(SynToMulticastDstIp);
}

static Codec* ctor(Module*)
{ return new TcpCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi tcp_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_TCP_NAME,
        CD_TCP_HELP,
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

//#ifdef BUILDING_SO
//SO_PUBLIC const BaseApi* snort_plugins[] =
//#else
const BaseApi* cd_tcp[] =
//#endif
{
    &tcp_api.base,
    nullptr
};

