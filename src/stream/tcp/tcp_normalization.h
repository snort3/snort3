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

// tcp_normalization.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 31, 2015

#ifndef TCP_NORMALIZATION_H
#define TCP_NORMALIZATION_H

#include "main/snort_types.h"
#include "framework/counts.h"
#include "perf_monitor/perf.h"
#include "protocols/tcp_options.h"
#include "protocols/tcp.h"
#include "normalize/normalize.h"
#include "packet_io/active.h"
#include "tcp_session.h"
#include "tcp_defs.h"

enum PegCounts
{
    PC_TCP_TRIM_SYN,
    PC_TCP_TRIM_RST,
    PC_TCP_TRIM_WIN,
    PC_TCP_TRIM_MSS,
    PC_TCP_ECN_SSN,
    PC_TCP_TS_NOP,
    PC_TCP_IPS_DATA,
    PC_TCP_BLOCK,
    PC_MAX
};

extern THREAD_LOCAL PegCount normStats[PC_MAX][NORM_MODE_MAX];

/* target-based policy types */
// changes to this enum require changes to stream_api.h::TCP_POLICIES
#define STREAM_POLICY_FIRST       1
#define STREAM_POLICY_LAST        2
#define STREAM_POLICY_LINUX       3
#define STREAM_POLICY_OLD_LINUX   4
#define STREAM_POLICY_BSD         5
#define STREAM_POLICY_MACOS       6
#define STREAM_POLICY_SOLARIS     7
#define STREAM_POLICY_IRIX        8
#define STREAM_POLICY_HPUX11      9
#define STREAM_POLICY_HPUX10     10
#define STREAM_POLICY_WINDOWS    11
#define STREAM_POLICY_WINDOWS2K3 12
#define STREAM_POLICY_VISTA      13
#define STREAM_POLICY_PROXY      14
#define STREAM_POLICY_DEFAULT    STREAM_POLICY_BSD

//-----------------------------------------------------------------------
// instead of centralizing all these normalizations so that
// Normalize_IsEnabled() is called only once, the checks and
// normalizations are localized.  this should lead to many
// fewer total checks.  however, it is best to minimize
// configuration checks on a per packet basis so there is
// still room for improvement.
static inline bool NormalDropPacketIf(Packet* p, NormFlags f)
{
    const NormMode mode = Normalize_GetMode(f);

    normStats[PC_TCP_BLOCK][mode]++;
    sfBase.iPegs[PERF_COUNT_TCP_BLOCK][mode]++;

    if (mode == NORM_MODE_ON)
    {
        Active::drop_packet(p);
        return true;
    }
    return false;
}

static inline bool NormalStripTimeStamp(Packet* p, const tcp::TcpOption* opt, NormMode mode)
{
    normStats[PC_TCP_TS_NOP][mode]++;
    sfBase.iPegs[PERF_COUNT_TCP_TS_NOP][mode]++;

    if (mode == NORM_MODE_ON)
    {
        // set raw option bytes to nops
        memset( ( void * ) opt, ( uint32_t ) tcp::TcpOptCode::NOP, tcp::TCPOLEN_TIMESTAMP);
        p->packet_flags |= PKT_MODIFIED;
        return true;
    }
    return false;
}

static inline void NormalTrimPayload(Packet* p, uint16_t max, TcpDataBlock* tdb)
{
    uint16_t fat = p->dsize - max;
    p->dsize = max;
    p->packet_flags |= (PKT_MODIFIED | PKT_RESIZED);
    tdb->end_seq -= fat;
}

static inline void NormalTrimPayloadIf(Packet* p, uint32_t max, TcpDataBlock* tdb, NormFlags flag,
        PegCounts peg, PerfCounts perf)
{
    const NormMode mode = Normalize_GetMode(flag);

    if (mode == NORM_MODE_ON)
        NormalTrimPayload(p, max, tdb);

    normStats[peg][mode]++;
    sfBase.iPegs[perf][mode]++;
}

static inline void NormalTrimPayloadIfSyn(Packet* p, uint32_t max, TcpDataBlock* tdb)
{
    if (p->dsize > max)
        NormalTrimPayloadIf(p, max, tdb, NORM_TCP_TRIM_SYN,
                PC_TCP_TRIM_SYN, PERF_COUNT_TCP_TRIM_SYN);
}

static inline void NormalTrimPayloadIfRst(Packet* p, uint32_t max, TcpDataBlock* tdb)
{
    if (p->dsize > max)
        NormalTrimPayloadIf(p, max, tdb, NORM_TCP_TRIM_RST, PC_TCP_TRIM_RST,
                PERF_COUNT_TCP_TRIM_RST);
}

static inline void NormalTrimPayloadIfWin(Packet* p, uint32_t max, TcpDataBlock* tdb)
{
    if (p->dsize > max)
        NormalTrimPayloadIf(p, max, tdb, NORM_TCP_TRIM_WIN, PC_TCP_TRIM_WIN,
                PERF_COUNT_TCP_TRIM_WIN);
}

static inline void NormalTrimPayloadIfMss(Packet* p, uint32_t max, TcpDataBlock* tdb)
{
    if (p->dsize > max)
        NormalTrimPayloadIf(p, max, tdb, NORM_TCP_TRIM_MSS, PC_TCP_TRIM_MSS,
                PERF_COUNT_TCP_TRIM_MSS);
}

static inline void NormalTrackECN(TcpSession* s, tcp::TCPHdr* tcph, int req3way)
{
    if (!s)
        return;

    if (tcph->is_syn_ack())
    {
        if (!req3way || s->ecn)
            s->ecn = ((tcph->th_flags & (TH_ECE | TH_CWR)) == TH_ECE);
    } else if (tcph->is_syn())
        s->ecn = tcph->are_flags_set(TH_ECE | TH_CWR);
}

static inline void NormalCheckECN(TcpSession* s, Packet* p)
{
    if (!s->ecn && (p->ptrs.tcph->th_flags & (TH_ECE | TH_CWR)))
    {
        const NormMode mode = Normalize_GetMode(NORM_TCP_ECN_STR);

        if (mode == NORM_MODE_ON)
        {
            ((tcp::TCPHdr*) p->ptrs.tcph)->th_flags &= ~(TH_ECE | TH_CWR);
            p->packet_flags |= PKT_MODIFIED;
        }
        normStats[PC_TCP_ECN_SSN][mode]++;
        sfBase.iPegs[PERF_COUNT_TCP_ECN_SSN][mode]++;
    }
}

const PegInfo* Stream_GetNormPegs();
NormPegs Stream_GetNormCounts(unsigned& c);

uint32_t StreamGetWindow(Flow* flow, TcpTracker* st, TcpDataBlock* tdb);
uint32_t StreamGetTcpTimestamp(Packet* p, uint32_t* ts, int strip);
int ValidTimestamp(TcpTracker *talker, TcpTracker *listener, TcpDataBlock *tdb, Packet *p,
        int *eventcode, int *got_ts);
int ValidRst(Flow* flow, TcpTracker *st, TcpDataBlock *tdb);
int RepeatedSyn(TcpTracker *listener, TcpTracker *talker, TcpDataBlock *tdb, TcpSession *tcpssn);

#endif
