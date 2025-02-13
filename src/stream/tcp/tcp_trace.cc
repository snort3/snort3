//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

// tcp_trace.cc author Oleksii Khomiakovskyi <okhomiak@cisco.com>
// based on work by davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_trace.h"

#include "trace/trace_api.h"

#include "tcp_module.h"
#include "tcp_session.h"
#include "tcp_stream_tracker.h"

static const char* const statext[] =
{
    "LST", "SYS", "SYR", "EST", "MDS", "MDR", "FW1", "FW2", "CLW",
    "CLG", "LAK", "TWT", "CLD", "NON"
};

const char* stream_tcp_state_to_str(const TcpStreamTracker& t)
{
    return statext[t.get_tcp_state()];
}

#define LCL(p, x) ((p).x() - (p).get_iss())
#define RMT(p, x, q) ((p).x - (q).get_iss())

static const char* const flushxt[] = { "IGN", "FPR", "PRE", "PRO", "PAF" };

inline void TraceEvent(const TcpSegmentDescriptor& tsd, uint32_t txd, uint32_t rxd,
    const snort::Packet* p)
{
    char flags[7] = "UAPRSF";
    const snort::tcp::TCPHdr* h = tsd.get_tcph();
    const char* order = "";
    const char* meta_ack_marker = tsd.is_meta_ack_packet() ? "M" : " ";

    if ( !h )
        return;

    for (int i = 0; i < 6; i++)
        if ( !((1 << (5 - i)) & h->th_flags) )
            flags[i] = '-';

    // force relative ack to zero if not conveyed
    if ( flags[1] != 'A' )
        rxd = tsd.get_ack();   // FIXIT-L SYN's seen with ack > 0 and ACK flag not set...

    if ( tsd.are_packet_flags_set(PKT_STREAM_ORDER_OK) )
        order = " (ins)";
    else if ( tsd.are_packet_flags_set(PKT_STREAM_ORDER_BAD) )
        order = " (oos)";

    uint32_t rseq = txd ? tsd.get_seq() - txd : tsd.get_seq();
    uint32_t rack = rxd ? tsd.get_ack() - rxd : tsd.get_ack();

    trace_logf(DEFAULT_TRACE_LOG_LEVEL, stream_tcp_trace, TRACE_STATE, p,
        FMTu64("-3") " %s %s=0x%02x Seq=%-4u Ack=%-4u Win=%-4u Len=%-4hu%s\n",
        tsd.get_packet_number(), meta_ack_marker, flags, h->th_flags, rseq, rack, tsd.get_wnd(),
        tsd.get_len(), order);
}

inline void TraceSession(const snort::Flow* flow, const snort::Packet* p)
{
    trace_logf(DEFAULT_TRACE_LOG_LEVEL, stream_tcp_trace, TRACE_STATE, p,
        "      LWS: ST=0x%x SF=0x%x CP=%hu SP=%hu\n", (unsigned)flow->session_state,
        flow->ssn_state.session_flags, flow->client_port, flow->server_port);
}

inline void TraceSegments(const TcpReassemblySegments& seglist, const snort::Packet* p)
{
    if ( !trace_enabled(stream_tcp_trace, TRACE_SEGMENTS) )
        return;

    const TcpSegmentNode* tsn = seglist.head;
    uint32_t sx = seglist.tracker->r_win_base;
    unsigned segs = 0;
    std::stringstream ss;

    while ( tsn )
    {
        uint32_t seq = tsn->start_seq();

        if ( SEQ_LT(sx, seq) )
            ss << " +" << seq - sx;

        else if ( SEQ_GT(sx, seq) )
            ss << " -" << sx - seq;

        ss << " " << tsn->length;

        if ( tsn->cursor and tsn->unscanned() > 0 )
            ss << "(" << tsn->cursor << "|" << tsn->unscanned() << ")";

        segs++;
        sx = seq + tsn->length;
        tsn = tsn->next;
    }

    if ( !ss.str().empty() )
        trace_logf(DEFAULT_TRACE_LOG_LEVEL, stream_tcp_trace, TRACE_SEGMENTS, p, "       %s\n", ss.str().c_str());
}

inline void TraceState(const TcpStreamTracker& a, const TcpStreamTracker& b, const char* s,
    const snort::Packet* p)
{
    uint32_t ua = a.get_snd_una() ? LCL(a, get_snd_una) : 0;
    uint32_t ns = a.get_snd_nxt() ? LCL(a, get_snd_nxt) : 0;

    trace_logf(DEFAULT_TRACE_LOG_LEVEL, stream_tcp_trace, TRACE_STATE, p,
        "      %s ST=%s      UA=%-4u NS=%-4u LW=%-5u RN=%-4u RW=%-4u ISS=%-4u IRS=%-4u\n",
        s, stream_tcp_state_to_str(a), ua, ns, a.get_snd_wnd( ),
        RMT(a, rcv_nxt, b), RMT(a, r_win_base, b), a.get_iss(), a.get_irs());

    unsigned paf = a.reassembler->is_splitter_paf() ? 2 : 0;
    unsigned fpt = a.get_flush_policy() ? 192 : 0;

    trace_logf(DEFAULT_TRACE_LOG_LEVEL, stream_tcp_trace, TRACE_STATE, p,
        "           FP=%s:%-4u SC=%-4u FL=%-4u SL=%-5u BS=%-4u\n",
        flushxt[a.get_flush_policy() + paf], fpt,
        a.seglist.get_seg_count(), a.seglist.get_flush_count(),
        a.seglist.get_seg_bytes_logical(),
        a.seglist.get_seglist_base_seq() - b.get_iss());

    TraceSegments(a.seglist, p);
}

void S5TraceTCP(const TcpSegmentDescriptor& tsd, const snort::Packet* p)
{
    TcpSession* ssn = (TcpSession*)tsd.get_flow()->session;
    assert(ssn);
    const TcpStreamTracker& srv = ssn->server;
    const TcpStreamTracker& cli = ssn->client;

    const char* cdir = "?";
    const char* sdir = "?";
    uint32_t txd = 0;
    uint32_t rxd = 0;

    if ( tsd.is_packet_from_client() )
    {
        sdir = "SRV<";
        cdir = "CLI>";
        txd = cli.get_iss();
        rxd = cli.get_irs();
    }
    else
    {
        sdir = "SRV>";
        cdir = "CLI<";
        txd = srv.get_iss();
        rxd = srv.get_irs();
    }

    TraceEvent(tsd, txd, rxd, p);

    if ( ssn->tcp_init )
        TraceSession(tsd.get_flow(), p);

    TraceState(cli, srv, cdir, p);
    TraceState(srv, cli, sdir, p);
}


