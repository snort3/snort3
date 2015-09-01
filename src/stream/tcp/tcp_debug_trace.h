//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

// tcp_debug_trace.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Aug 5, 2015

#ifndef TCP_DEBUG_TRACE_H
#define TCP_DEBUG_TRACE_H

#include "protocols/tcp.h"

#ifndef REG_TEST
#define S5TraceTCP(pkt, flow, tdb, evt)
#else
#define LCL(p, x)    (p->x - p->isn)
#define RMT(p, x, q) (p->x - (q ? q->isn : 0))

static const char* const statext[] =
{
    "NON", "LST", "SYR", "SYS", "EST", "CLW",
    "LAK", "FW1", "CLG", "FW2", "TWT", "CLD"
};

static const char* const flushxt[] = { "IGN", "FPR", "PRE", "PRO", "PAF" };

// FIXIT-L this should not be thread specific
static THREAD_LOCAL int s5_trace_enabled = -1;

static inline void TraceEvent(const Packet* p, TcpDataBlock*, uint32_t txd, uint32_t rxd)
{
    int i;
    char flags[7] = "UAPRSF";
    const tcp::TCPHdr* h = p->ptrs.tcph;
    const char* order = "";

    if (!h)
        return;

    for (i = 0; i < 6; i++)
        if (!((1 << (5 - i)) & h->th_flags))
            flags[i] = '-';

    // force relative ack to zero if not conveyed
    if (flags[1] != 'A')
        rxd = ntohl(h->th_ack);

    if (p->packet_flags & PKT_STREAM_ORDER_OK)
        order = " (ins)";
    else if (p->packet_flags & PKT_STREAM_ORDER_BAD)
        order = " (oos)";

    fprintf(stdout, "\n" FMTu64("-3") " %s=0x%02x Seq=%-4u Ack=%-4u Win=%-4u Len=%-4u%s\n",
            //"\n" FMTu64("-3") " %s=0x%02x Seq=%-4u Ack=%-4u Win=%-4u Len=%-4u End=%-4u%s\n",
            pc.total_from_daq, flags, h->th_flags, ntohl(h->th_seq) - txd, ntohl(h->th_ack) - rxd, ntohs(h->th_win),
            p->dsize, order);
}

static inline void TraceSession(const Flow* lws)
{
    fprintf( stdout, "    LWS: ST=0x%x SF=0x%x CP=%u SP=%u\n", (unsigned)lws->session_state,
            lws->ssn_state.session_flags, lws->client_port, lws->server_port );
}

static inline void TraceSegments(const TcpTracker* a)
{
    TcpSegment* ss = a->seglist;
    uint32_t sx = a->r_win_base;
    unsigned segs = 0, bytes = 0;

    while (ss)
    {
        if (SEQ_LT(sx, ss->seq))
            fprintf(stdout, " +%u", ss->seq - sx);
        else if (SEQ_GT(sx, ss->seq))
            fprintf(stdout, " -%u", sx - ss->seq);

        fprintf(stdout, " %u", ss->size);

        segs++;
        bytes += ss->size;

        sx = ss->seq + ss->size;
        ss = ss->next;
    }
    assert(a->seg_count == segs);
    assert(a->seg_bytes_logical == bytes);
}

static inline void TraceState(const TcpTracker* a, const TcpTracker* b, const char* s)
{
    uint32_t why = a->l_nxt_seq ? LCL(a, l_nxt_seq) : 0;

    fprintf(stdout, "    %s ST=%s:%02x   UA=%-4u NS=%-4u LW=%-5u RN=%-4u RW=%-4u ", s, statext[a->s_mgr.state],
            a->s_mgr.sub_state, LCL(a, l_unackd), why, a->l_window, RMT(a, r_nxt_ack, b), RMT(a, r_win_base, b));

    if (a->s_mgr.state_queue)
        fprintf(stdout, "QS=%s QC=0x%02x QA=%-4u", statext[a->s_mgr.state_queue], a->s_mgr.expected_flags,
                RMT(a, s_mgr.transition_seq, b));
    fprintf(stdout, "\n");
    unsigned paf = (a->splitter and a->splitter->is_paf()) ? 2 : 0;
    unsigned fpt = a->flush_policy ? 192 : 0;

    fprintf( stdout, "         FP=%s:%-4u SC=%-4u FL=%-4u SL=%-5u BS=%-4u", flushxt[a->flush_policy + paf], fpt,
            a->seg_count, a->flush_count, a->seg_bytes_logical, a->seglist_base_seq - b->isn);

    if (s5_trace_enabled == 2)
        TraceSegments(a);

    fprintf(stdout, "\n");
}

static inline void TraceTCP(const Packet* p, const Flow* lws, TcpDataBlock* tdb, int event)
{
    const TcpSession* ssn = (TcpSession*) lws->session;
    const TcpTracker* srv = ssn ? &ssn->server : NULL;
    const TcpTracker* cli = ssn ? &ssn->client : NULL;

    const char* cdir = "?", *sdir = "?";
    uint32_t txd = 0, rxd = 0;

    if (p->packet_flags & PKT_FROM_SERVER)
    {
        sdir = "SRV>";
        cdir = "CLI<";

        if (ssn->tcp_init)
        {
            txd = srv->isn;
            rxd = cli->isn;
        }
    } else if (p->packet_flags & PKT_FROM_CLIENT)
    {
        sdir = "SRV<";
        cdir = "CLI>";

        if (ssn->tcp_init)
        {
            txd = cli->isn;
            rxd = srv->isn;
        }
    }
    TraceEvent(p, tdb, txd, rxd);

    if (!ssn->tcp_init)
        return;

    if (lws && ssn->lws_init)
        TraceSession(lws);

    if (lws && !event)
    {
        TraceState(cli, srv, cdir);
        TraceState(srv, cli, sdir);
    }
}

static inline void S5TraceTCP(const Packet* p, const Flow* lws, TcpDataBlock* tdb, int event)
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

    TraceTCP(p, lws, tdb, event);
}
#endif  // REG_TEST

#endif

