//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

// stream_log.cc author Steven Baigal <sbaigal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_log.h"

#include <cassert>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <sstream>

#include "detection/ips_context.h"
#include "main/thread.h"
#include "packet_io/packet_tracer.h"
#include "protocols/eth.h"
#include "protocols/icmp4.h"
#include "protocols/ip.h"
#include "protocols/layer.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/tcp_options.h"
#include "stream/tcp/tcp_module.h"
#include "stream/tcp/tcp_trace.h"
#include "trace/trace_api.h"
#include "utils/util.h"

using namespace snort;

static constexpr unsigned STREAM_DAQ_BUF_SIZE = 2048;

THREAD_LOCAL char stream_daq_buf[STREAM_DAQ_BUF_SIZE] = {};
THREAD_LOCAL unsigned stream_daq_buf_len = 0;
THREAD_LOCAL int64_t stream_daq_ts = 0;

namespace
{

const char* strip_stream_module_name(const char* msg)
{
    static const char* const prefixes[] = {
        "stream_tcp: ", "stream_udp: ", "stream_icmp: ",
        "stream_ip: ", "Stream: ", "Flow: ", "Session: ", nullptr
    };

    for ( const char* const* pfx = prefixes; *pfx; ++pfx )
    {
        size_t len = strlen(*pfx);
        if ( strncmp(msg, *pfx, len) == 0 )
            return msg + len;
    }

    return msg;
}

void stream_daq_buf_append(const char* msg)
{
    unsigned space = STREAM_DAQ_BUF_SIZE - stream_daq_buf_len;
    if ( space == 0 )
        return;

    int written = snprintf(stream_daq_buf + stream_daq_buf_len, space, "%s", msg);
    if ( written < 0 )
        return;

    unsigned written_len = (unsigned)written;
    if ( written_len < space )
        stream_daq_buf_len += written_len;
    else
        stream_daq_buf_len = STREAM_DAQ_BUF_SIZE - 1;

    stream_daq_ts = (int64_t)PacketTracer::get_time();
}

std::string stringify_tcp_options(const Packet* const pkt)
{
    std::ostringstream oss;
    tcp::TcpOptIterator iter(pkt->ptrs.tcph, pkt);

    for ( const tcp::TcpOption& opt : iter )
    {
        switch ( opt.code )
        {
        case tcp::TcpOptCode::WSCALE:
            oss << "ws " << (uint16_t)opt.data[0] << ", ";
            break;
        case tcp::TcpOptCode::MAXSEG:
            oss << "mss " << ntohs(*((const uint16_t*)(opt.data))) << ", ";
            break;
        case tcp::TcpOptCode::SACKOK:
            oss << "sack OK, ";
            break;
        default:
            break;
        }
    }

    std::string opts = oss.str();
    if ( !opts.empty() )
    {
        opts.insert(0, "options [");
        opts.replace(opts.size() - 2, 2, "] ");
    }

    return opts;
}

} // namespace

void stream_daq_log_start()
{
    stream_daq_buf_len = 0;
    stream_daq_buf[0] = '\0';
}

void stream_daq_log_end(Packet*)
{
    if ( stream_daq_buf_len == 0 or !PacketTracer::is_daq_activated() )
        return;

    if ( stream_daq_buf[stream_daq_buf_len - 1] == '\n' )
        stream_daq_buf[--stream_daq_buf_len] = '\0';

    PacketTracer::daq_log("stream+%" PRId64 "++%s$",
        stream_daq_ts, stream_daq_buf);
}

void stream_log(const Packet* p, const char* fmt, ...)
{
    const bool packet_trace_active = PacketTracer::is_active();
    const bool daq_trace_active = PacketTracer::is_daq_activated();
    const bool cbd_trace_active = stream_tcp_trace_enabled;

    if ( !UNLIKELY(packet_trace_active or daq_trace_active or cbd_trace_active) )
        return;

    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if ( packet_trace_active )
        (buf[0] == '\n' && buf[1] == '\0') ? PacketTracer::log("\n") : PacketTracer::log("%s", buf);

    if ( daq_trace_active )
        stream_daq_buf_append(strip_stream_module_name(buf));

    if ( cbd_trace_active )
    {
        const char* msg = strip_stream_module_name(buf);
        trace_logf(TRACE_INFO_LEVEL, stream_tcp_trace,
            TRACE_STATE, p, "%s", msg);
    }
}

void flow_log(const char* fmt, ...)
{
    if ( !PacketTracer::is_active() and !PacketTracer::is_daq_activated() )
        return;

    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if ( PacketTracer::is_active() )
        PacketTracer::log("%s", buf);

    if ( PacketTracer::is_daq_activated() )
        stream_daq_buf_append(strip_stream_module_name(buf));
}

void StreamLog::add_ip_header_info(const Packet& p, bool add_eth)
{
    PacketTracer* pkt_trace = PacketTracer::s_pkt_trace;
    bool shell_format = pkt_trace and pkt_trace->shell_enabled and !pkt_trace->daq_activated;

    SfIpString sipstr;
    SfIpString dipstr;
    std::ostringstream oss;

    uint16_t sport = p.ptrs.sp;
    uint16_t dport = p.ptrs.dp;

    if ( p.type() == PktType::ICMP )
    {
        assert(p.ptrs.icmph);
        sport = p.ptrs.icmph ? p.ptrs.icmph->type : 0;
        dport = 0;
    }

    const SfIp* actual_sip = p.ptrs.ip_api.get_src();
    const SfIp* actual_dip = p.ptrs.ip_api.get_dst();
    IpProtocol proto = p.get_ip_proto_next();

    actual_sip->ntop(sipstr, sizeof(sipstr));
    actual_dip->ntop(dipstr, sizeof(dipstr));

    if ( shell_format )
    {
        PacketTracer::log("\n");
        oss << sipstr << " " << sport << " -> "
            << dipstr << " " << dport << " "
            << std::to_string(to_utype(proto))
            << " AS=" << p.pkth->address_space_id
            << " ID=" << get_relative_instance_number();

        if ( p.is_inter_group_flow() )
        {
            oss << " GR="
                << p.pkth->ingress_group
                << "-"
                << p.pkth->egress_group;
        }

        if ( p.pkth->tenant_id )
            oss << " TN=" << p.pkth->tenant_id;

        oss << " ";
        pkt_trace->debugstr = oss.str();
    }
    else
    {
        if ( add_eth ) add_eth_header_info(p);

        oss << sipstr << ":" << sport << " -> "
            << dipstr << ":" << dport << " "
            << "proto " << std::to_string(to_utype(proto))
            << " AS=" << p.pkth->address_space_id
            << " ID=" << get_relative_instance_number();

        if ( p.is_inter_group_flow() )
        {
            oss << " GR="
                << p.pkth->ingress_group
                << "-"
                << p.pkth->egress_group;
        }

        if ( p.pkth->tenant_id )
            oss << " TN=" << p.pkth->tenant_id;

        oss << "\n";
        stream_log(&p, "%s", oss.str().c_str());
    }

    add_packet_type_info(p);
}

void StreamLog::add_packet_type_info(const Packet& p)
{
    bool is_v6 = p.ptrs.ip_api.is_ip6();
    char timestamp[TIMEBUF_SIZE];
    ts_print((const struct timeval*)&p.pkth->ts, timestamp);

    switch ( p.type() )
    {
    case PktType::TCP:
    {
        char tcpFlags[10];
        p.ptrs.tcph->stringify_flags(tcpFlags);

        std::string opts;
        if ( p.ptrs.tcph->th_flags & TH_SYN )
            opts = stringify_tcp_options(&p);

        if ( p.ptrs.tcph->th_flags & TH_ACK )
            stream_log(&p, "Packet %" PRIu64 ": TCP %s, %s, seq %u, ack %u, win %u, %sdsize %u%s\n",
                p.context->packet_number, tcpFlags, timestamp,
                p.ptrs.tcph->seq(), p.ptrs.tcph->ack(), p.ptrs.tcph->win(), opts.c_str(), p.dsize,
                p.is_retry() ? ", retry pkt" : "");
        else
            stream_log(&p, "Packet %" PRIu64 ": TCP %s, %s, seq %u, win %u, %sdsize %u%s\n",
                p.context->packet_number, tcpFlags, timestamp, p.ptrs.tcph->seq(),
                p.ptrs.tcph->win(), opts.c_str(), p.dsize,
                p.is_retry() ? ", retry pkt" : "");

        DAQ_PktTcpAckData_t* tcp_mack =
            (DAQ_PktTcpAckData_t*)p.daq_msg->meta[DAQ_PKT_META_TCP_ACK_DATA];
        if ( tcp_mack )
        {
            stream_log(&p, "Meta_ack: ack %u, win %u\n",
                ntohl(tcp_mack->tcp_ack_seq_num), ntohs(tcp_mack->tcp_window_size));
        }
        break;
    }

    case PktType::ICMP:
    {
        const char* icmp_str = is_v6 ? "ICMPv6" : "ICMP";

        stream_log(&p, "Packet %" PRIu64 ": %s, %s, Type: %u  Code: %u \n",
            p.context->packet_number, icmp_str, timestamp,
            p.ptrs.icmph->type, p.ptrs.icmph->code);
        break;
    }

    default:
        stream_log(&p, "Packet %" PRIu64 ": %s, %s\n",
            p.context->packet_number, p.get_type(), timestamp);
        break;
    }
}

void StreamLog::add_eth_header_info(const Packet& p)
{
    PacketTracer* pkt_trace = PacketTracer::s_pkt_trace;
    bool shell_format = pkt_trace and pkt_trace->shell_enabled and !pkt_trace->daq_activated;

    auto eh = layer::get_eth_layer(&p);
    if ( !eh )
        return;

    if ( shell_format )
    {
        PacketTracer::log("\n");
        std::ostringstream oss;
        oss << eh->to_string()
            << " AS=" << p.pkth->address_space_id
            << " ID=" << get_relative_instance_number();

        if ( p.is_inter_group_flow() )
        {
            oss << " GR="
                << p.pkth->ingress_group
                << "-"
                << p.pkth->egress_group;
        }

        if ( p.pkth->tenant_id )
            oss << " TN=" << p.pkth->tenant_id;

        oss << " ";
        pkt_trace->debugstr = oss.str();
        pkt_trace->active = true;
    }
    else
        stream_log(&p, "%s\n", eh->to_string().c_str());
}

void StreamLog::add_tunnel_info(const Packet& p)
{
    if ( !PacketTracer::is_active() and !PacketTracer::is_daq_activated() and !stream_is_cbd_enabled() )
        return;

    std::vector<TunnelInfo> tunnels = layer::get_encapsulation_layers(&p);
    if ( tunnels.empty() )
        return;

    for ( const auto& tunnel : tunnels )
    {
        SfIpString src_str;
        SfIpString dst_str;
        tunnel.src_ip.ntop(src_str, sizeof(src_str));
        tunnel.dst_ip.ntop(dst_str, sizeof(dst_str));

        const char* tunnel_name = layer::get_tunnel_type_name(tunnel.tunnel_type);

        if ( tunnel.has_ports )
        {
            stream_log(&p, "Tunnel=%s %s:%u -> %s:%u proto %u\n",
                tunnel_name,
                src_str, static_cast<unsigned>(tunnel.src_port),
                dst_str, static_cast<unsigned>(tunnel.dst_port),
                static_cast<unsigned>(tunnel.ip_proto));
        }
        else
        {
            stream_log(&p, "Tunnel=%s %s -> %s ports=n/a proto %u\n",
                tunnel_name,
                src_str, dst_str,
                static_cast<unsigned>(tunnel.ip_proto));
        }
    }
}

bool StreamLog::stream_is_cbd_enabled(void)
{
    return stream_tcp_trace_enabled;
}
