//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// tcp_debug_trace.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Aug 5, 2015

#ifndef TCP_DEBUG_TRACE_H
#define TCP_DEBUG_TRACE_H

#include "utils/stats.h"

#include "tcp_reassemblers.h"

#ifndef REG_TEST
#define S5TraceTCP(pkt, flow, tsd, evt)
#else
#define LCL(p, x)    ((p)->x() - (p)->get_iss())
#define RMT(p, x, q) ((p)->x - ((q) ? (q)->get_iss() : 0))

static const char* const statext[] =
{
    "LST", "SYS", "SYR", "EST", "FW1", "FW2", "CLW",
    "CLG", "LAK", "TWT", "CLD", "NON"
};

static const char* const flushxt[] = { "IGN", "FPR", "PRE", "PRO", "PAF" };

static THREAD_LOCAL int s5_trace_enabled = -1;  // FIXIT-L should use module trace feature

inline void TraceEvent(
    const snort::Packet* p, TcpSegmentDescriptor*, uint32_t txd, uint32_t rxd)
{
    int i;
    char flags[7] = "UAPRSF";
    const snort::tcp::TCPHdr* h = p->ptrs.tcph;
    const char* order = "";

    if (!h)
        return;

    for (i = 0; i < 6; i++)
        if (!((1 << (5 - i)) & h->th_flags))
            flags[i] = '-';

    // force relative ack to zero if not conveyed
    if (flags[1] != 'A')
        rxd = h->ack();   // FIXIT-L SYN's seen with ack > 0 and ACK flag not set...

    if (p->packet_flags & PKT_STREAM_ORDER_OK)
        order = " (ins)";
    else if (p->packet_flags & PKT_STREAM_ORDER_BAD)
        order = " (oos)";

    uint32_t rseq = ( txd ) ? h->seq() - txd : h->seq();
    uint32_t rack = ( rxd ) ? h->ack() - rxd : h->ack();
    fprintf(stdout, "\n" FMTu64("-3") " %s=0x%02x Seq=%-4u Ack=%-4u Win=%-4hu Len=%-4hu%s\n",
        //"\n" FMTu64("-3") " %s=0x%02x Seq=%-4u Ack=%-4u Win=%-4u Len=%-4u End=%-4u%s\n",
        p->context->packet_number, flags, h->th_flags, rseq, rack, h->win(), p->dsize, order);
}

inline void TraceSession(const snort::Flow* lws)
{
    fprintf(stdout, "    LWS: ST=0x%x SF=0x%x CP=%hu SP=%hu\n", (unsigned)lws->session_state,
        lws->ssn_state.session_flags, lws->client_port, lws->server_port);
}

inline void TraceState(TcpStreamTracker* a, TcpStreamTracker* b, const char* s)
{
    uint32_t ua = a->get_snd_una() ? LCL(a, get_snd_una) : 0;
    uint32_t ns = a->get_snd_nxt() ? LCL(a, get_snd_nxt) : 0;

    fprintf(stdout,
        "    %s ST=%s      UA=%-4u NS=%-4u LW=%-5u RN=%-4u RW=%-4u ISS=%-4u IRS=%-4u ",
        s, statext[a->get_tcp_state()], ua, ns, a->get_snd_wnd( ),
        RMT(a, rcv_nxt, b), RMT(a, r_win_base, b), a->get_iss(), a->get_irs());

    fprintf(stdout, "\n");
    unsigned paf = (a->splitter and a->splitter->is_paf()) ? 2 : 0;
    unsigned fpt = a->flush_policy ? 192 : 0;

    fprintf(stdout, "         FP=%s:%-4u SC=%-4u FL=%-4u SL=%-5u BS=%-4u",
        flushxt[a->flush_policy + paf], fpt,
        a->reassembler.get_seg_count(), a->reassembler.get_flush_count(),
        a->reassembler.get_seg_bytes_logical(),
        a->reassembler.get_seglist_base_seq() - b->get_iss());

    if (s5_trace_enabled == 2)
        a->reassembler.trace_segments();

    fprintf(stdout, "\n");
}

inline void TraceTCP(
    const snort::Packet* p, const snort::Flow* lws, TcpSegmentDescriptor* tsd, int event)
{
    TcpSession* ssn = (TcpSession*)lws->session;
    TcpStreamTracker* srv = ssn ? &ssn->server : nullptr;
    TcpStreamTracker* cli = ssn ? &ssn->client : nullptr;

    const char* cdir = "?", * sdir = "?";
    uint32_t txd = 0, rxd = 0;

    if (p->is_from_server())
    {
        sdir = "SRV>";
        cdir = "CLI<";

        txd = srv->get_iss();
        rxd = srv->get_irs();
    }
    else if ( p->is_from_client() )
    {
        sdir = "SRV<";
        cdir = "CLI>";

        txd = cli->get_iss();
        rxd = cli->get_irs();
    }
    TraceEvent(p, tsd, txd, rxd);

    if ( lws && ssn->lws_init)
        TraceSession(lws);

    if (lws && !event)
    {
        TraceState(cli, srv, cdir);
        TraceState(srv, cli, sdir);
    }
}

inline void S5TraceTCP(
    const snort::Packet* p, const snort::Flow* lws, TcpSegmentDescriptor* tsd, int event)
{
    if (!s5_trace_enabled)
        return;

    if (s5_trace_enabled < 0)
    {
        const char* s5t = getenv("S5_TRACE");

        if (!s5t)
        {
            s5_trace_enabled = 0;
            return;
        }

        // no error checking required - atoi() is sufficient
        s5_trace_enabled = atoi(s5t);
    }

    TraceTCP(p, lws, tsd, event);
}
#endif  // REG_TEST

#endif

