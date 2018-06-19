//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2007-2013 Sourcefire, Inc.
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

// @file    log_text.c
// @author  Russ Combs <rcombs@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "log_text.h"

#include <sfbpf_dlt.h>

#include "detection/detection_engine.h"
#include "detection/signature.h"
#include "events/event.h"
#include "main/snort_config.h"
#include "network_inspectors/appid/appid_api.h"
#include "packet_io/sfdaq.h"
#include "protocols/eth.h"
#include "protocols/gre.h"
#include "protocols/icmp4.h"
#include "protocols/ipv4_options.h"
#include "protocols/packet_manager.h"
#include "protocols/tcp.h"
#include "protocols/tcp_options.h"
#include "protocols/udp.h"
#include "utils/util.h"
#include "utils/util_net.h"

#include "log.h"
#include "messages.h"
#include "obfuscator.h"

namespace snort
{
/*--------------------------------------------------------------------
 * utility functions
 *--------------------------------------------------------------------
 */
void LogTimeStamp(TextLog* log, Packet* p)
{
    char timestamp[TIMEBUF_SIZE];
    ts_print((const struct timeval*)&p->pkth->ts, timestamp);
    TextLog_Puts(log, timestamp);
}

/*--------------------------------------------------------------------
 * alert stuff cloned from log.c
 *--------------------------------------------------------------------
 */
/*--------------------------------------------------------------------
 * prints out priority data associated with an alert
 *--------------------------------------------------------------------
 */
void LogPriorityData(TextLog* log, const Event& e)
{
    if ((e.sig_info->class_type != nullptr)
        && (e.sig_info->class_type->name != nullptr))
    {
        TextLog_Print(log, "[Classification: %s] ", e.sig_info->class_type->name);
    }

    TextLog_Print(log, "[Priority: %d] ", e.sig_info->priority);
}

/*--------------------------------------------------------------------
 * Purpose: Prints out AppID data associated with an alert
 *
 *--------------------------------------------------------------------
 */
bool LogAppID(TextLog* log, Packet* p)
{
    if ( p->flow )
    {
        const char* app_name = appid_api.get_application_name(*p->flow, p->is_from_client());

        if ( app_name )
        {
            TextLog_Print(log, "[AppID: %s] ", app_name);
            return true;
        }
    }

    return false;
}

/*--------------------------------------------------------------------
 * layer 2 header stuff cloned from log.c
 *--------------------------------------------------------------------
 */

static void LogEthHeader(TextLog* log, Packet* p)
{
    const eth::EtherHdr* eh = layer::get_eth_layer(p);

    /* src addr */
    TextLog_Print(log, "%02X:%02X:%02X:%02X:%02X:%02X -> ", eh->ether_src[0],
        eh->ether_src[1], eh->ether_src[2], eh->ether_src[3],
        eh->ether_src[4], eh->ether_src[5]);

    /* dest addr */
    TextLog_Print(log, "%02X:%02X:%02X:%02X:%02X:%02X ", eh->ether_dst[0],
        eh->ether_dst[1], eh->ether_dst[2], eh->ether_dst[3],
        eh->ether_dst[4], eh->ether_dst[5]);

    /* protocol and pkt size */
    TextLog_Print(log, "type:0x%X len:0x%X\n", ntohs(eh->ether_type),
        p->pkth->pktlen);
}

static void LogMPLSHeader(TextLog* log, Packet* p)
{
    TextLog_Print(log,"label:0x%05X exp:0x%X bos:0x%X ttl:0x%X\n",
        p->ptrs.mplsHdr.label, p->ptrs.mplsHdr.exp, p->ptrs.mplsHdr.bos, p->ptrs.mplsHdr.ttl);
}

static void LogGREHeader(TextLog* log, Packet* p)
{
    const gre::GREHdr* greh = layer::get_gre_layer(p);

    if (greh == nullptr)
        return;

    TextLog_Print(log, "GRE version:%u flags:0x%02X ether-type:0x%04X\n",
        greh->get_version(), greh->flags, greh->proto());
}

/*--------------------------------------------------------------------
 * prints second layer header info
 *--------------------------------------------------------------------
 */
void Log2ndHeader(TextLog* log, Packet* p)
{
    if ( !p or !p->num_layers )
        return;

    if ( SFDAQ::get_base_protocol() == DLT_EN10MB )
        LogEthHeader(log, p);

    else if ( SnortConfig::log_verbose() )
        ErrorMessage("Datalink %i (not supported)\n", SFDAQ::get_base_protocol());
}

/*-------------------------------------------------------------------
 * IP stuff cloned from log.c
 *-------------------------------------------------------------------
 */

static void LogIpOptions(TextLog* log, const ip::IpOptionIterator& options)
{
    unsigned c = 0;

    for (const auto& opt : options)
    {
        UNUSED(opt);
        c++;
    }

    // can happen if hlen() > 20, but first option is invalid
    if (c == 0)
        return;

    TextLog_Print(log, "IP Options (%u) => ", c);

    for (auto op : options)
    {
        switch (op.code)
        {
        case ip::IPOptionCodes::RR:
            TextLog_Puts(log, "RR ");
            break;

        case ip::IPOptionCodes::EOL:
            TextLog_Puts(log, "EOL ");
            break;

        case ip::IPOptionCodes::NOP:
            TextLog_Puts(log, "NOP ");
            break;

        case ip::IPOptionCodes::TS:
            TextLog_Puts(log, "TS ");
            break;

        case ip::IPOptionCodes::ESEC:
            TextLog_Puts(log, "ESEC ");
            break;

        case ip::IPOptionCodes::SECURITY:
            TextLog_Puts(log, "SEC ");
            break;

        case ip::IPOptionCodes::LSRR:
        case ip::IPOptionCodes::LSRR_E:
            TextLog_Puts(log, "LSRR ");
            break;

        case ip::IPOptionCodes::SATID:
            TextLog_Puts(log, "SID ");
            break;

        case ip::IPOptionCodes::SSRR:
            TextLog_Puts(log, "SSRR ");
            break;

        case ip::IPOptionCodes::RTRALT:
            TextLog_Puts(log, "RTRALT ");
            break;

        default:
            // the only cases where op.len is invalid were handled aboved
            // op.len includes code and length bytes but data does not
            TextLog_Print(log, "Type %u, Len %u", op.code, op.len);

            if ( op.len <= 2 )
                break;

            TextLog_Print(log, " |%02X", op.data[0]);

            for ( unsigned j = 1, n = op.len - 2; j < n; ++j )
                TextLog_Print(log, " %02X", op.data[j]);

            TextLog_Print(log, "| ");
            break;
        }
    }
    TextLog_NewLine(log);
}

void LogIpOptions(TextLog* log, const ip::IP4Hdr* ip4h, uint16_t valid_ip4_len)
{
    const ip::IpOptionIterator options(ip4h, valid_ip4_len);
    LogIpOptions(log, options);
}

static void LogIpOptions(TextLog* log, const ip::IP4Hdr* ip4h, const Packet* const p)
{
    const ip::IpOptionIterator options(ip4h, p);
    LogIpOptions(log, options);
}

/*--------------------------------------------------------------------
 * dump the IP addresses to the given TextLog, handles obfuscation
 *--------------------------------------------------------------------
 */
void LogIpAddrs(TextLog* log, Packet* p)
{
    if ( p->is_fragment() || (!p->is_tcp() && !p->is_udp() && !p->is_data()) )
    {
        const char* ip_fmt = "%s -> %s";
        InetBuf src, dst;

        if (SnortConfig::obfuscate())
        {
            ObfuscateIpToText(p->ptrs.ip_api.get_src(),
                SnortConfig::get_conf()->homenet, SnortConfig::get_conf()->obfuscation_net, src);

            ObfuscateIpToText(p->ptrs.ip_api.get_dst(),
                SnortConfig::get_conf()->homenet, SnortConfig::get_conf()->obfuscation_net, dst);

            TextLog_Print(log, ip_fmt, src, dst);
        }
        else
        {
            TextLog_Print(log, ip_fmt,
                sfip_ntop(p->ptrs.ip_api.get_src(), src, sizeof(src)),
                sfip_ntop(p->ptrs.ip_api.get_dst(), dst, sizeof(dst)));
        }
    }
    else
    {
        const char* ip_fmt = "%s:%d -> %s:%d";
        InetBuf src, dst;

        if (SnortConfig::obfuscate())
        {
            ObfuscateIpToText(p->ptrs.ip_api.get_src(),
                SnortConfig::get_conf()->homenet, SnortConfig::get_conf()->obfuscation_net, src);

            ObfuscateIpToText(p->ptrs.ip_api.get_dst(),
                SnortConfig::get_conf()->homenet, SnortConfig::get_conf()->obfuscation_net, dst);

            TextLog_Print(log, ip_fmt, src, p->ptrs.sp, dst, p->ptrs.dp);
        }
        else
        {
            TextLog_Print(log, ip_fmt,
                sfip_ntop(p->ptrs.ip_api.get_src(), src, sizeof(src)), p->ptrs.sp,
                sfip_ntop(p->ptrs.ip_api.get_dst(), dst, sizeof(dst)), p->ptrs.dp);
        }
    }
}

/*--------------------------------------------------------------------
 * dump the IP header info to the given TextLog
 *--------------------------------------------------------------------
 */
void LogIPHeader(TextLog* log, Packet* p)
{
    if(!p->ptrs.ip_api.is_ip())
    {
        TextLog_Print(log, "IP header truncated\n");
        return;
    }

    LogIpAddrs(log, p);

    if (!SnortConfig::output_datalink())
    {
        TextLog_NewLine(log);
    }
    else
    {
        TextLog_Putc(log, ' ');
    }

    // ip_api will return nullptr
    const bool is_ip6 = p->ptrs.ip_api.is_ip6();
    const ip::IP4Hdr* const ip4h = p->ptrs.ip_api.get_ip4h(); // nullptr if ipv6
    uint16_t frag_off;

    /* Since the ip_api needs to do an 'if' statement every time to
     * determine if this is ip6 vs ip4, I'm optimizing this print
     * statement by checking only once
     */
    if (is_ip6)
    {
        const ip::IP6Hdr* const ip6h = p->ptrs.ip_api.get_ip6h(); // nullptr if ipv4
        const ip::IP6Frag* const ip6_frag = // nullptr if ipv4
            (is_ip6 ? layer::get_inner_ip6_frag() : nullptr);

        TextLog_Print(log, "%s TTL:%u TOS:0x%X ID:%u IpLen:%u DgmLen:%u",
            protocol_names[to_utype(p->get_ip_proto_next())],
            ip6h->hop_lim(),
            ip6h->tos(),
            (ip6_frag ? ip6_frag->id() : 0),
            ip::IP6_HEADER_LEN,
            (ip6h->len() + ip::IP6_HEADER_LEN));

        if (!ip6_frag)
        {
            frag_off = 0;
        }
        else
        {
            if (ip6_frag->rb())
                TextLog_Puts(log, " RB");

            if (ip6_frag->mf())
                TextLog_Puts(log, " MF");

            frag_off = ip6_frag->off();
        }
    }
    else
    {
        TextLog_Print(log, "%s TTL:%u TOS:0x%X ID:%u IpLen:%u DgmLen:%u",
            protocol_names[to_utype(ip4h->proto())],
            ip4h->ttl(),
            ip4h->tos(),
            ip4h->id(),
            ip4h->hlen(),
            ip4h->len());

        if (ip4h->rb())
            TextLog_Puts(log, " RB");

        if (ip4h->df())
            TextLog_Puts(log, " DF");

        if (ip4h->mf())
            TextLog_Puts(log, " MF");

        frag_off = ip4h->off();
    }

    TextLog_NewLine(log);

    /* print IP options */
    if (!is_ip6)
    {
        if (ip4h->has_options())
            LogIpOptions(log, ip4h, p);
    }

    /* print fragment info if necessary */
    if ( p->is_fragment() )
    {
        TextLog_Print(log, "Frag Offset: 0x%04X   Frag Size: 0x%04X\n",
            frag_off, p->ptrs.ip_api.pay_len());
    }
}

static void LogOuterIPHeader(TextLog* log, Packet* p)
{
    uint8_t save_frag_flag = (p->ptrs.decode_flags & DECODE_FRAG);
    uint16_t save_sp, save_dp;
    ip::IpApi save_ip_api = p->ptrs.ip_api;

    p->ptrs.decode_flags &= ~DECODE_FRAG;

    if (p->proto_bits & PROTO_BIT__TEREDO)
    {
        save_sp = p->ptrs.sp;
        save_dp = p->ptrs.dp;

        const udp::UDPHdr* udph = layer::get_outer_udp_lyr(p);
        p->ptrs.sp = ntohs(udph->uh_sport);
        p->ptrs.dp = ntohs(udph->uh_dport);

        LogIPHeader(log, p);

        p->ptrs.sp = save_sp;
        p->ptrs.dp = save_dp;
    }
    else
    {
        PktType tmp_type = p->type();
        p->ptrs.set_pkt_type(PktType::IP);
        LogIPHeader(log, p);
        p->ptrs.set_pkt_type(tmp_type);
    }

    p->ptrs.ip_api = save_ip_api;
    p->packet_flags |= save_frag_flag;
}

/*-------------------------------------------------------------------
 * TCP stuff cloned from log.c
 *-------------------------------------------------------------------
 */
inline uint16_t extract_16_bits(const uint8_t* const buf)
{ return ntohs(*((const uint16_t*)(buf)) ); }

inline uint32_t extract_32_bits(const uint8_t* const buf)
{ return ntohl(*((const uint32_t*)(buf)) ); }

static void LogTcpOptions(TextLog* log, const tcp::TcpOptIterator& opt_iter)
{
    unsigned c = 0;

    for (const tcp::TcpOption& opt : opt_iter)
    {
        UNUSED(opt);
        c++;
    }

    // can happen if hlen() > MIN_HEADER_LEN, but first option is invalid
    if (c == 0)
        return;

    TextLog_Print(log, "TCP Options (%u) =>", c);

    for (const tcp::TcpOption& opt : opt_iter)
    {
        switch (opt.code)
        {
        case tcp::TcpOptCode::MAXSEG:
            TextLog_Print(log, " MSS: %u", extract_16_bits(opt.data));
            break;

        case tcp::TcpOptCode::EOL:
            TextLog_Puts(log, " EOL");
            break;

        case tcp::TcpOptCode::NOP:
            TextLog_Puts(log, " NOP");
            break;

        case tcp::TcpOptCode::WSCALE:
            TextLog_Print(log, " WS: %u", opt.data[0]);
            break;

        case tcp::TcpOptCode::SACK:
        {
            /* This length was not check during tcp decode */
            uint16_t val1, val2;

            if (opt.len >= 4)
            {
                val1 = extract_16_bits(opt.data);
                val2 = extract_16_bits(opt.data + 2);
            }
            else if (opt.len >= 2)
            {
                val1 = extract_16_bits(opt.data);
                val2 = 0;
            }
            else
            {
                val1 = 0;
                val2 = 0;
            }

            TextLog_Print(log, " Sack: %u@%u", val1, val2);
            break;
        }
        case tcp::TcpOptCode::SACKOK:
            TextLog_Puts(log, " SackOK ");
            break;

        case tcp::TcpOptCode::ECHO:
            TextLog_Print(log, " Echo: %u", extract_32_bits(opt.data));
            break;

        case tcp::TcpOptCode::ECHOREPLY:
            TextLog_Print(log, " Echo Rep: %u", extract_32_bits(opt.data));
            break;

        case tcp::TcpOptCode::TIMESTAMP:
            TextLog_Print(log, " TS: %u %u", extract_32_bits(opt.data),
                extract_32_bits(opt.data + 4));
            break;

        case tcp::TcpOptCode::CC:
            TextLog_Print(log, " CC %u", extract_32_bits(opt.data));
            break;

        case tcp::TcpOptCode::CC_NEW:
            TextLog_Print(log, " CCNEW: %u", extract_32_bits(opt.data));
            break;

        case tcp::TcpOptCode::CC_ECHO:
            TextLog_Print(log, " CCECHO: %u", extract_32_bits(opt.data));
            break;

        default:
            TextLog_Print(log, " Kind %u, Len %u", opt.code, opt.len);

            if ( opt.len <= 2 )
                break;

            TextLog_Print(log, " |%02X",  opt.data[0]);

            for ( unsigned i = 1, n = opt.len - 2; i < n; ++i )
                TextLog_Print(log, " %02X",  opt.data[i]);

            TextLog_Print(log, "|");
            break;
        }
    }
}

void LogTcpOptions(TextLog* log,  const tcp::TCPHdr* tcph, uint16_t valid_tcp_len)
{
    const tcp::TcpOptIterator opt_iter(tcph, valid_tcp_len);
    LogTcpOptions(log, opt_iter);
}

static void LogTcpOptions(TextLog* log, const Packet* const p)
{
    tcp::TcpOptIterator opt_iter(p->ptrs.tcph, p);
    LogTcpOptions(log, opt_iter);
}

/*--------------------------------------------------------------------
 * dump the TCP header info to the given TextLog
 *--------------------------------------------------------------------
 */
void LogTCPHeader(TextLog* log, Packet* p)
{
    char tcpFlags[9];
    const tcp::TCPHdr* tcph = p->ptrs.tcph;

    if (tcph == nullptr)
    {
        TextLog_Print(log, "TCP header truncated\n");
        return;
    }
    /* print TCP flags */
    CreateTCPFlagString(tcph, tcpFlags);
    TextLog_Puts(log, tcpFlags); /* We don't care about the NULL */

    /* print other TCP info */
    TextLog_Print(log, " Seq: 0x%lX  Ack: 0x%lX  Win: 0x%X  TcpLen: %d",
        (u_long)ntohl(tcph->th_seq),
        (u_long)ntohl(tcph->th_ack),
        ntohs(tcph->th_win), tcph->off());

    if ((tcph->th_flags & TH_URG) != 0)
    {
        TextLog_Print(log, "  UrgPtr: 0x%X\n", tcph->urp());
    }
    else
    {
        TextLog_NewLine(log);
    }

    /* dump the TCP options */
    if (tcph->has_options())
    {
        LogTcpOptions(log, p);
        TextLog_NewLine(log);
    }
}

/*-------------------------------------------------------------------
 * UDP stuff cloned from log.c
 *-------------------------------------------------------------------
 */
/*--------------------------------------------------------------------
 * dump the UDP header to the given TextLog
 *--------------------------------------------------------------------
 */
void LogUDPHeader(TextLog* log, Packet* p)
{
    if (p->ptrs.udph == nullptr)
    {
        TextLog_Print(log, "UDP header truncated\n");
        return;
    }
    /* not much to do here... */
    TextLog_Print(log, "Len: %d\n", ntohs(p->ptrs.udph->uh_len) - udp::UDP_HEADER_LEN);
}

/*--------------------------------------------------------------------
 * ICMP stuff cloned from log.c
 *--------------------------------------------------------------------
 */
/*--------------------------------------------------------------------
 * prints the 64 bits of the original IP payload in an ICMP packet
 * that requires it
 *--------------------------------------------------------------------
 */
static void LogEmbeddedICMPHeader(TextLog* log, const ICMPHdr* icmph)
{
    if (log == nullptr || icmph == nullptr)
        return;

    TextLog_Print(log, "Type: %d  Code: %d  Csum: %u",
        icmph->type, icmph->code, ntohs(icmph->csum));

    switch (icmph->type)
    {
    case ICMP_DEST_UNREACH:
    case ICMP_TIME_EXCEEDED:
    case ICMP_SOURCE_QUENCH:
        break;

    case ICMP_PARAMETERPROB:
        if (icmph->code == 0)
            TextLog_Print(log, "  Ptr: %u", icmph->s_icmp_pptr);
        break;

    case ICMP_REDIRECT:
// XXX-IPv6 "NOT YET IMPLEMENTED - ICMP printing"
        break;

    case ICMP_ECHO:
    case ICMP_ECHOREPLY:
    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
    case ICMP_INFO_REQUEST:
    case ICMP_INFO_REPLY:
    case ICMP_ADDRESS:
    case ICMP_ADDRESSREPLY:
        TextLog_Print(log, "  Id: %u  SeqNo: %u",
            ntohs(icmph->s_icmp_id), ntohs(icmph->s_icmp_seq));
        break;

    case ICMP_ROUTER_ADVERTISE:
        TextLog_Print(log, "  Addrs: %u  Size: %u  Lifetime: %u",
            icmph->s_icmp_num_addrs, icmph->s_icmp_wpa,
            ntohs(icmph->s_icmp_lifetime));
        break;

    default:
        break;
    }

    TextLog_NewLine(log);
}

/*--------------------------------------------------------------------
 * prints the original/encapsulated IP header + 64 bits of the
 * original IP payload in an ICMP packet
 *--------------------------------------------------------------------
 */
static void LogICMPEmbeddedIP(TextLog* log, Packet* p)
{
    if (log == nullptr || p == nullptr)
        return;

    // FIXIT-L -- Allocating a new Packet here is ridiculously excessive.
    Packet* orig_p = new Packet;
    Packet& op = *orig_p;

    if (!layer::set_api_ip_embed_icmp(p, op.ptrs.ip_api))
    {
        TextLog_Puts(log, "\nORIGINAL DATAGRAM TRUNCATED");
    }
    else
    {
        switch (p->proto_bits & PROTO_BIT__ICMP_EMBED)
        {
        case PROTO_BIT__TCP_EMBED_ICMP:
        {
            const tcp::TCPHdr* const tcph = layer::get_tcp_embed_icmp(op.ptrs.ip_api);
            if (tcph)
            {
                orig_p->ptrs.sp = tcph->src_port();
                orig_p->ptrs.dp = tcph->dst_port();
                orig_p->ptrs.tcph = tcph;
                orig_p->ptrs.set_pkt_type(PktType::TCP);

                TextLog_Print(log, "\n** ORIGINAL DATAGRAM DUMP:\n");
                LogIPHeader(log, orig_p);

                TextLog_Print(log, "Seq: 0x%lX\n",
                    (u_long)ntohl(orig_p->ptrs.tcph->th_seq));
            }
            break;
        }

        case PROTO_BIT__UDP_EMBED_ICMP:
        {
            const udp::UDPHdr* const udph = layer::get_udp_embed_icmp(op.ptrs.ip_api);
            if (udph)
            {
                orig_p->ptrs.sp = udph->src_port();
                orig_p->ptrs.dp = udph->dst_port();
                orig_p->ptrs.udph = udph;
                orig_p->ptrs.set_pkt_type(PktType::UDP);

                TextLog_Print(log, "\n** ORIGINAL DATAGRAM DUMP:\n");
                LogIPHeader(log, orig_p);
                TextLog_Print(log, "Len: %d  Csum: %d\n",
                    udph->len() - udp::UDP_HEADER_LEN,
                    udph->cksum());
            }
            break;
        }

        case PROTO_BIT__ICMP_EMBED_ICMP:
        {
            TextLog_Print(log, "\n** ORIGINAL DATAGRAM DUMP:\n");
            LogIPHeader(log, orig_p);

            const icmp::ICMPHdr* icmph = layer::get_icmp_embed_icmp(op.ptrs.ip_api);
            if (icmph != nullptr)
                LogEmbeddedICMPHeader(log, icmph);
            break;
        }

        default:
        {
            TextLog_Print(log, "\n** ORIGINAL DATAGRAM DUMP:\n");
            LogIPHeader(log, orig_p);

            TextLog_Print(log, "Protocol: 0x%X (unknown or "
                "header truncated)", orig_p->ptrs.ip_api.proto());
            break;
        }
        } /* switch */

        /* if more than 8 bytes of original IP payload sent */

        const int16_t more_bytes = p->dsize - 8;
        if (more_bytes > 0)
        {
            TextLog_Print(log, "(%d more bytes of original packet)\n",
                more_bytes);
        }

        TextLog_Puts(log, "** END OF DUMP");
    }

    delete orig_p;
}

/*--------------------------------------------------------------------
 * print ICMP header
 *--------------------------------------------------------------------
 */
void LogICMPHeader(TextLog* log, Packet* p)
{
    /* 32 digits plus 7 colons and a NULL byte */
    char buf[8*4 + 7 + 1];

    if (p->ptrs.icmph == nullptr)
    {
        TextLog_Puts(log, "ICMP header truncated\n");
        return;
    }

    TextLog_Print(log, "Type:%d  Code:%d  ", p->ptrs.icmph->type, p->ptrs.icmph->code);

    switch (p->ptrs.icmph->type)
    {
    case ICMP_ECHOREPLY:
        TextLog_Print(log, "ID:%d  Seq:%d  ", ntohs(p->ptrs.icmph->s_icmp_id),
            ntohs(p->ptrs.icmph->s_icmp_seq));
        TextLog_Puts(log, "ECHO REPLY");
        break;

    case ICMP_DEST_UNREACH:
        TextLog_Puts(log, "DESTINATION UNREACHABLE: ");
        switch (p->ptrs.icmph->code)
        {
        case ICMP_NET_UNREACH:
            TextLog_Puts(log, "NET UNREACHABLE");
            break;

        case ICMP_HOST_UNREACH:
            TextLog_Puts(log, "HOST UNREACHABLE");
            break;

        case ICMP_PROT_UNREACH:
            TextLog_Puts(log, "PROTOCOL UNREACHABLE");
            break;

        case ICMP_PORT_UNREACH:
            TextLog_Puts(log, "PORT UNREACHABLE");
            break;

        case ICMP_FRAG_NEEDED:
            TextLog_Print(log, "FRAGMENTATION NEEDED, DF SET\n"
                "NEXT LINK MTU: %u",
                ntohs(p->ptrs.icmph->s_icmp_nextmtu));
            break;

        case ICMP_SR_FAILED:
            TextLog_Puts(log, "SOURCE ROUTE FAILED");
            break;

        case ICMP_NET_UNKNOWN:
            TextLog_Puts(log, "NET UNKNOWN");
            break;

        case ICMP_HOST_UNKNOWN:
            TextLog_Puts(log, "HOST UNKNOWN");
            break;

        case ICMP_HOST_ISOLATED:
            TextLog_Puts(log, "HOST ISOLATED");
            break;

        case ICMP_PKT_FILTERED_NET:
            TextLog_Puts(log, "ADMINISTRATIVELY PROHIBITED NETWORK FILTERED");
            break;

        case ICMP_PKT_FILTERED_HOST:
            TextLog_Puts(log, "ADMINISTRATIVELY PROHIBITED HOST FILTERED");
            break;

        case ICMP_NET_UNR_TOS:
            TextLog_Puts(log, "NET UNREACHABLE FOR TOS");
            break;

        case ICMP_HOST_UNR_TOS:
            TextLog_Puts(log, "HOST UNREACHABLE FOR TOS");
            break;

        case ICMP_PKT_FILTERED:
            TextLog_Puts(log, "ADMINISTRATIVELY PROHIBITED,\nPACKET FILTERED");
            break;

        case ICMP_PREC_VIOLATION:
            TextLog_Puts(log, "PREC VIOLATION");
            break;

        case ICMP_PREC_CUTOFF:
            TextLog_Puts(log, "PREC CUTOFF");
            break;

        default:
            TextLog_Puts(log, "UNKNOWN");
            break;
        }

        LogICMPEmbeddedIP(log, p);
        break;

    case ICMP_SOURCE_QUENCH:
        TextLog_Puts(log, "SOURCE QUENCH");
        LogICMPEmbeddedIP(log, p);
        break;

    case ICMP_REDIRECT:
        TextLog_Puts(log, "REDIRECT");
        switch (p->ptrs.icmph->code)
        {
        case ICMP_REDIR_NET:
            TextLog_Puts(log, " NET");
            break;

        case ICMP_REDIR_HOST:
            TextLog_Puts(log, " HOST");
            break;

        case ICMP_REDIR_TOS_NET:
            TextLog_Puts(log, " TOS NET");
            break;

        case ICMP_REDIR_TOS_HOST:
            TextLog_Puts(log, " TOS HOST");
            break;

        default:
            break;
        }

/* written this way since inet_ntoa was typedef'ed to use sfip_ntoa
 * which requires SfIp instead of inaddr's.  This call to inet_ntoa
 * is a rare case that doesn't use SfIp's. */

// XXX-IPv6 NOT YET IMPLEMENTED - IPV6 addresses technically not supported - need to change ICMP

        /* no inet_ntop in Windows */
        snort_inet_ntop(AF_INET, (const void*)(&p->ptrs.icmph->s_icmp_gwaddr.s_addr),
            buf, sizeof(buf));
        TextLog_Print(log, " NEW GW: %s", buf);

        LogICMPEmbeddedIP(log, p);

        break;

    case ICMP_ECHO:
        TextLog_Print(log, "ID:%d   Seq:%d  ", ntohs(p->ptrs.icmph->s_icmp_id),
            ntohs(p->ptrs.icmph->s_icmp_seq));
        TextLog_Puts(log, "ECHO");
        break;

    case ICMP_ROUTER_ADVERTISE:
        TextLog_Print(log, "ROUTER ADVERTISEMENT: "
            "Num addrs: %d Addr entry size: %d Lifetime: %u",
            p->ptrs.icmph->s_icmp_num_addrs, p->ptrs.icmph->s_icmp_wpa,
            ntohs(p->ptrs.icmph->s_icmp_lifetime));
        break;

    case ICMP_ROUTER_SOLICIT:
        TextLog_Puts(log, "ROUTER SOLICITATION");
        break;

    case ICMP_TIME_EXCEEDED:
        TextLog_Puts(log, "TTL EXCEEDED");
        switch (p->ptrs.icmph->code)
        {
        case ICMP_TIMEOUT_TRANSIT:
            TextLog_Puts(log, " IN TRANSIT");
            break;

        case ICMP_TIMEOUT_REASSY:
            TextLog_Puts(log, " TIME EXCEEDED IN FRAG REASSEMBLY");
            break;

        default:
            break;
        }

        LogICMPEmbeddedIP(log, p);

        break;

    case ICMP_PARAMETERPROB:
        TextLog_Puts(log, "PARAMETER PROBLEM");
        switch (p->ptrs.icmph->code)
        {
        case ICMP_PARAM_BADIPHDR:
            TextLog_Print(log, ": BAD IP HEADER BYTE %u",
                p->ptrs.icmph->s_icmp_pptr);
            break;

        case ICMP_PARAM_OPTMISSING:
            TextLog_Puts(log, ": OPTION MISSING");
            break;

        case ICMP_PARAM_BAD_LENGTH:
            TextLog_Puts(log, ": BAD LENGTH");
            break;

        default:
            break;
        }

        LogICMPEmbeddedIP(log, p);

        break;

    case ICMP_TIMESTAMP:
        TextLog_Print(log, "ID: %u  Seq: %u  TIMESTAMP REQUEST",
            ntohs(p->ptrs.icmph->s_icmp_id), ntohs(p->ptrs.icmph->s_icmp_seq));
        break;

    case ICMP_TIMESTAMPREPLY:
        TextLog_Print(log, "ID: %u  Seq: %u  TIMESTAMP REPLY:\n"
            "Orig: %u Rtime: %u  Ttime: %u",
            ntohs(p->ptrs.icmph->s_icmp_id), ntohs(p->ptrs.icmph->s_icmp_seq),
            p->ptrs.icmph->s_icmp_otime, p->ptrs.icmph->s_icmp_rtime,
            p->ptrs.icmph->s_icmp_ttime);
        break;

    case ICMP_INFO_REQUEST:
        TextLog_Print(log, "ID: %u  Seq: %u  INFO REQUEST",
            ntohs(p->ptrs.icmph->s_icmp_id), ntohs(p->ptrs.icmph->s_icmp_seq));
        break;

    case ICMP_INFO_REPLY:
        TextLog_Print(log, "ID: %u  Seq: %u  INFO REPLY",
            ntohs(p->ptrs.icmph->s_icmp_id), ntohs(p->ptrs.icmph->s_icmp_seq));
        break;

    case ICMP_ADDRESS:
        TextLog_Print(log, "ID: %u  Seq: %u  ADDRESS REQUEST",
            ntohs(p->ptrs.icmph->s_icmp_id), ntohs(p->ptrs.icmph->s_icmp_seq));
        break;

    case ICMP_ADDRESSREPLY:
        TextLog_Print(log, "ID: %u  Seq: %u  ADDRESS REPLY: 0x%08X",
            ntohs(p->ptrs.icmph->s_icmp_id), ntohs(p->ptrs.icmph->s_icmp_seq),
            (u_int)ntohl(p->ptrs.icmph->s_icmp_mask));
        break;

    default:
        TextLog_Puts(log, "UNKNOWN");
        break;
    }

    TextLog_NewLine(log);
}

/*--------------------------------------------------------------------
 * reference stuff cloned from signature.c
 *--------------------------------------------------------------------
 */
static void LogReference(TextLog* log, ReferenceNode* refNode)
{
    if (refNode)
    {
        if (refNode->system)
        {
            if (refNode->system->url)
                TextLog_Print(log, "[Xref => %s%s]", refNode->system->url,
                    refNode->id);
            else
                TextLog_Print(log, "[Xref => %s %s]", refNode->system->name,
                    refNode->id);
        }
        else
        {
            TextLog_Print(log, "[Xref => %s]", refNode->id);
        }
    }
}

/*
 * prints out cross reference data associated with an alert
 */
void LogXrefs(TextLog* log, const Event& e)
{
    ReferenceNode* refNode = e.sig_info->refs;

    while ( refNode )
    {
        LogReference(log, refNode);
        refNode = refNode->next;
    }
}

/*--------------------------------------------------------------------
 * payload stuff cloned from log.c
 *--------------------------------------------------------------------
 */
/*--------------------------------------------------------------------
 * dump the printable ASCII data from a packet
 *--------------------------------------------------------------------
 */
static void LogCharData(TextLog* log, const uint8_t* data, int len)
{
    const uint8_t* pb = data;
    const uint8_t* end = data + len;
    int lineCount = 0;

    if ( !data )
    {
        return;
    }

    while ( pb < end )
    {
        if ( *pb > 0x1F && *pb < 0x7F)
        {   /* printable */
            TextLog_Putc(log, *pb);
        }
        else
        {   /* not printable */
            TextLog_Putc(log, '.');
        }

        if ( ++lineCount == 64 )
        {
            TextLog_Putc(log, ' ');
            TextLog_NewLine(log);
            lineCount = 0;
        }
        pb++;
    }
    /* slam a \n on the back */
    TextLog_Putc(log, ' ');
    TextLog_NewLine(log);
    TextLog_Putc(log, ' ');
}

// do a side by side dump of a buffer with hex on
// the left and decoded ASCII on the right

struct HexAsciiLayout
{
    unsigned bytes_per_frame;
    unsigned frame_break;
    bool break_text;

    const char* offset_fmt;
    const char* offset_hdr;

    const char* separator;
    const char* padding;
};

static const HexAsciiLayout hal_std =
{
    16, 7, true, "%04.4X  ", "- -   ",
    "- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -",
//  "41 02 43 04 45 06 47 08  49 0A 4B 0C 4D 0E 4F 0F  A.C.E.G. I.K.M.O."
    "                                                 "
};

static const HexAsciiLayout hal_wide =
{
    20, 9, false, "%5u  ", "- - -  ",
    "- - - - - - - - - - - - - - -  - - - - - - - - - - - - - - -  - - - - -  - - - - -",
//  "41 02 43 04 45 06 47 08 49 0A  4B 0C 4D 0E 4F 0F 01 02 03 04  A.C.E.G.I.K.M.O....."
    "                                                             "
};

static void obfuscate(Packet* p, const uint8_t* data, int& ip_ob_start, int& ip_ob_end)
{
    assert(p);
    ip_ob_start = ip_ob_end = -1;

    if ( !SnortConfig::obfuscate() )
        return;

    const ProtocolIndex ipv4_idx = PacketManager::proto_idx(ProtocolId::IPIP);
    const ProtocolIndex ipv6_idx = PacketManager::proto_idx(ProtocolId::IPV6);

    unsigned num_layers = p->num_layers;
    ProtocolIndex lyr_idx = 0;
    unsigned i;

    for ( i = 0; i < num_layers; i++ )
    {
        lyr_idx = PacketManager::proto_idx(p->layers[i].prot_id);

        if ( lyr_idx == ipv4_idx || lyr_idx == ipv6_idx)
        {
            if (p->layers[i].length && p->layers[i].start)
                break;
        }
    }

    int ip_start = p->layers[i].start - data;

    if (ip_start > 0 )
    {
        ip_ob_start = ip_start + 10;
        if (lyr_idx == ipv4_idx)
            ip_ob_end = ip_ob_start + 2 + 2*(sizeof(struct in_addr));
        else
            ip_ob_end = ip_ob_start + 2 + 2*(sizeof(struct in6_addr));
    }
}

void LogNetData(
    TextLog* log, const uint8_t* data, const int len, Packet* p, const char* buf_name)
{
    if ( !len )
        return;

    int ip_ob_start, ip_ob_end;

    if ( buf_name )
        ip_ob_start = ip_ob_end = -1;
    else
    {
        obfuscate(p, data, ip_ob_start, ip_ob_end);
        buf_name = p->get_pseudo_type();
    }

    const HexAsciiLayout& hal = SnortConfig::get_conf()->output_wide_hex() ? hal_wide : hal_std;
    const char* hdr_off = SnortConfig::verbose_byte_dump() ? hal.offset_hdr : "";
    const char* ins_name = p->flow and p->flow->gadget ?  p->flow->gadget->get_name() : "snort";

    TextLog_Print(log, "\n%s.%s[%u]:\n", ins_name, buf_name, len);
    TextLog_Print(log, "%s%s\n", hdr_off, hal.separator);

    const uint8_t* pb = data;
    const uint8_t* end = data + len;

    int offset = 0;

    /* loop thru the whole buffer */
    while ( pb < end )
    {
        if (SnortConfig::verbose_byte_dump())
        {
            TextLog_Print(log, hal.offset_fmt, offset);
            offset += hal.bytes_per_frame;
        }
        int byte_pos = 0;
        unsigned i;

        /* process one frame first print the binary as ascii hex */
        for (i = 0; i < hal.bytes_per_frame && pb+i < end; i++, byte_pos++)
        {
            if ((byte_pos >= ip_ob_start) && (byte_pos < ip_ob_end))
                TextLog_Quote(log, "XX ");
            else
                TextLog_Print(log, "%2.2X ", pb[i]);

            if ( i == hal.frame_break )
                TextLog_Putc(log, ' ');
        }
        int char_pos = 0;

        /* print ' ' past end of packet and before ascii */
        unsigned fb = (0 < i and i < hal.frame_break) ? 1 : 0;
        TextLog_Puts(log, hal.padding+(3*i)-fb);

        /* then print the actual ascii chars or a '.' for control chars */
        for (unsigned j = 0; j < hal.bytes_per_frame && pb+j < end; j++, char_pos++)
        {
            if ((char_pos >= ip_ob_start) && (char_pos < ip_ob_end))
                TextLog_Putc(log, 'X');
            else
            {
                if ( 0x1F < pb[j] and pb[j] < 0x7F)
                    TextLog_Putc(log, pb[j]);
                else
                    TextLog_Putc(log, '.');
            }
            if ( j == hal.frame_break and hal.break_text )
                TextLog_Putc(log, ' ');
        }
        pb += hal.bytes_per_frame;
        TextLog_NewLine(log);
    }
    TextLog_Print(log, "%s%s\n", hdr_off, hal.separator);
}

/*--------------------------------------------------------------------
 * dump the packet to the given TextLog
 *--------------------------------------------------------------------
 */

void LogIPPkt(TextLog* log, Packet* p)
{
    if ( SnortConfig::output_datalink() )
    {
        Log2ndHeader(log, p);

        if ( p->proto_bits & PROTO_BIT__MPLS )
            LogMPLSHeader(log, p);

        // FIXIT-L log all layers in order
        ip::IpApi tmp_api = p->ptrs.ip_api;
        int8_t num_layer = 0;
        IpProtocol tmp_next = p->get_ip_proto_next();
        bool first = true;

        while (layer::set_outer_ip_api(p, p->ptrs.ip_api, p->ip_proto_next, num_layer) &&
            tmp_api != p->ptrs.ip_api)
        {
            LogOuterIPHeader(log, p);

            if (first)
            {
                LogGREHeader(log, p); // checks for valid gre layer before logging
                first = false;
            }
        }

        p->ip_proto_next = tmp_next;
        p->ptrs.ip_api = tmp_api;
    }

    LogIPHeader(log, p);

    /* if this isn't a fragment, print the other header info */
    if (!(p->ptrs.decode_flags & DECODE_FRAG))
    {
        switch (p->type())
        {
        case PktType::TCP:
            if ( p->ptrs.tcph != nullptr )
                LogTCPHeader(log, p);
            else
                LogNetData(log, p->ptrs.ip_api.ip_data(), p->ptrs.ip_api.pay_len(), p);
            break;

        case PktType::UDP:
            if ( p->ptrs.udph != nullptr )
            {
                // for consistency, nothing to log (tcp doesn't log paylen)
                LogUDPHeader(log, p);
            }
            else
            {
                LogNetData(log, p->ptrs.ip_api.ip_data(), p->ptrs.ip_api.pay_len(), p);
            }

            break;

        case PktType::ICMP:
            // FIXIT-L log accurate ICMP6 data.
            if (p->is_ip6())
                break;

            if ( p->ptrs.icmph != nullptr )
                LogICMPHeader(log, p);
            else
                LogNetData(log, p->ptrs.ip_api.ip_data(), p->ptrs.ip_api.pay_len(), p);
            break;

        default:
            break;
        }
    }
    LogPayload(log, p);
}

void LogPayload(TextLog* log, Packet* p)
{
    /* dump the application layer data */
    if (SnortConfig::output_app_data() && !SnortConfig::verbose_byte_dump())
    {
        if (SnortConfig::output_char_data())
        {
            LogCharData(log, p->data, p->dsize);

            DataPointer file_data;
            DetectionEngine::get_file_data(file_data);

            if ( file_data.len > 0 )
            {
                TextLog_Print(log, "%s\n", "File data");
                LogCharData(log, file_data.data, file_data.len);
            }
        }
        else
        {
            if ( p->obfuscator )
            {
                // FIXIT-P avoid string copy
                std::string buf((const char*)p->data, p->dsize);

                for ( const auto& b : *p->obfuscator )
                    buf.replace(b.offset, b.length, b.length, p->obfuscator->get_mask_char());

                LogNetData(log, (const uint8_t*)buf.c_str(), p->dsize, p);
            }
            else
            {
                LogNetData(log, p->data, p->dsize, p);

                DataPointer file_data;
                DetectionEngine::get_file_data(file_data);

                if ( file_data.len > 0 )
                {
                    TextLog_Print(log, "%s\n", "File data");
                    LogNetData(log, file_data.data, file_data.len, p);
                }
            }
        }
    }
    else if (SnortConfig::verbose_byte_dump())
    {
        LogNetData(log, p->pkt, p->pkth->caplen, p);
    }
}
} // namespace snort

