//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// paf.cc author Russ Combs <rcombs@sourcefire.com>

#include "paf.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "stream/stream.h"
#include "stream/stream_api.h"

//--------------------------------------------------------------------
// private state
//--------------------------------------------------------------------

typedef enum
{
    FT_NOP,  // no flush
    FT_SFP,  // abort paf
    FT_PAF,  // flush to paf pt when len >= paf
    FT_LIMIT,  // flush to paf pt, don't update flags
    FT_MAX   // flush len when len >= max
} FlushType;

static THREAD_LOCAL uint64_t prep_calls = 0;
static THREAD_LOCAL uint64_t prep_bytes = 0;

// s5_len and s5_idx are used only during the
// lifetime of paf_check()
// FIXIT-L these thread local should be moved into thread context
static THREAD_LOCAL uint32_t s5_len;  // total bytes queued
static THREAD_LOCAL uint32_t s5_idx;  // offset from start of queued bytes

#define PAF_LIMIT_FUZZ 1500

// 255 is max pseudo-random flush point; eth mtu ensures that maximum flushes
// are not trimmed which throws off the tracking total in stream5_paf.c
// max paf max = max datagram - eth mtu - 255 = 63780
#define MAX_PAF_MAX (65535 -  PAF_LIMIT_FUZZ - 255)

//--------------------------------------------------------------------

static uint32_t paf_flush (
    StreamSplitter*, PAF_State* ps, FlushType ft, uint32_t* flags)
{
    uint32_t at = 0;
    *flags &= ~(PKT_PDU_HEAD | PKT_PDU_TAIL);

    DebugFormat(DEBUG_STREAM_PAF,
        "%s: type=%d, fpt=%u, len=%u, tot=%u\n",
        __func__, ft, ps->fpt, s5_len, ps->tot);

    switch ( ft )
    {
    case FT_NOP:
        return -1;

    case FT_SFP:
        *flags = 0;
        return -1;

    case FT_PAF:
        at = ps->fpt;
        *flags |= PKT_PDU_TAIL;
        break;

    case FT_LIMIT:
        if (ps->fpt > s5_len)
        {
            at = s5_len;
            ps->fpt -= s5_len;
        }
        else
        {
            at = ps->fpt;
            ps->fpt = s5_len - ps->fpt; // number of characters scanned but not flushing
        }
        break;

    // use of s5_len is suboptimal here because the actual amount
    // flushed is determined later and can differ in certain cases
    // such as exceeding s5_pkt->max_dsize.  the actual amount
    // flushed would ideally be applied to ps->fpt later.  for
    // now we try to circumvent such cases so we track correctly.
    //
    // FIXIT-L max_dsize should no longer be exceeded since it excludes headers.
    case FT_MAX:
        at = s5_len;
        if ( ps->fpt > s5_len )
            ps->fpt -= s5_len;
        else
            ps->fpt = 0;
        break;
    }

    if ( !at || !s5_len )
        return -1;

    // safety - prevent seq + at < seq
    if ( at > 0x7FFFFFFF )
        at = 0x7FFFFFFF;

    if ( !ps->tot )
        *flags |= PKT_PDU_HEAD;

    if ( *flags & PKT_PDU_TAIL )
        ps->tot = 0;
    else
        ps->tot += at;

    return at;
}

//--------------------------------------------------------------------

static bool paf_callback (
    StreamSplitter* ss, PAF_State* ps, Flow* ssn,
    const uint8_t* data, uint32_t len, uint32_t flags)
{
    ps->paf = ss->scan(ssn, data, len, flags, &ps->fpt);

    if ( ps->paf == StreamSplitter::ABORT )
        return false;

    if ( ps->paf != StreamSplitter::SEARCH )
    {
        ps->fpt += s5_idx;

        if ( ps->fpt <= s5_len )
        {
            s5_idx = ps->fpt;
            return true;
        }
    }
    s5_idx = s5_len;
    return false;
}

//--------------------------------------------------------------------

static inline bool paf_eval (
    StreamSplitter* ss, PAF_State* ps, Flow* ssn,
    uint32_t flags, const uint8_t* data, uint32_t len, FlushType* ft)
{
    DebugFormat(DEBUG_STREAM_PAF,
        "%s: paf=%d, idx=%u, len=%u, fpt=%u\n",
        __func__, ps->paf, s5_idx, s5_len, ps->fpt);

    uint16_t fuzz = 0; // FIXIT-L PAF add a little zippedy-do-dah

    switch ( ps->paf )
    {
    case StreamSplitter::SEARCH:
        if ( s5_len > s5_idx )
        {
            return paf_callback(ss, ps, ssn, data, len, flags);
        }
        return false;

    case StreamSplitter::FLUSH:
        if ( s5_len >= ps->fpt )
        {
            *ft = FT_PAF;
            ps->paf = StreamSplitter::SEARCH;
            return true;
        }
        if ( s5_len >= ss->max(ssn) + fuzz )
        {
            *ft = FT_MAX;
            return false;
        }
        return false;

    case StreamSplitter::LIMIT:
        // if we are within PAF_LIMIT_FUZZ character of paf_max ...
        if ( s5_len + PAF_LIMIT_FUZZ >= ss->max(ssn) + fuzz)
        {
            *ft = FT_LIMIT;
            ps->paf = StreamSplitter::LIMITED;
            return false;
        }
        ps->paf = StreamSplitter::SEARCH;
        return false;

    case StreamSplitter::SKIP:
        if ( s5_len > ps->fpt )
        {
            if ( ps->fpt > s5_idx )
            {
                uint32_t delta = ps->fpt - s5_idx;
                if ( delta > len )
                    return false;
                data += delta;
                len -= delta;
            }
            s5_idx = ps->fpt;
            return paf_callback(ss, ps, ssn, data, len, flags);
        }
        return false;

    case StreamSplitter::LIMITED:
        // increment position by previously scanned bytes. set in paf_flush
        ps->paf = StreamSplitter::SEARCH;
        s5_idx += ps->fpt;
        ps->fpt = 0;
        return true;

    default:
        // StreamSplitter::ABORT || StreamSplitter::START
        break;
    }

    *ft = FT_SFP;
    return false;
}

//--------------------------------------------------------------------
// public stuff
//--------------------------------------------------------------------

void paf_setup (PAF_State* ps)
{
    // this is already cleared when instantiated
    //memset(ps, 0, sizeof(*ps));
    ps->paf = StreamSplitter::START;
}

void paf_reset (PAF_State* ps)
{
    memset(ps, 0, sizeof(*ps));
    ps->paf = StreamSplitter::START;
}

void paf_clear (PAF_State* ps)
{
    ps->paf = StreamSplitter::ABORT;
}

//--------------------------------------------------------------------

int32_t paf_check (
    StreamSplitter* ss, PAF_State* ps, Flow* ssn,
    const uint8_t* data, uint32_t len, uint32_t total,
    uint32_t seq, uint32_t* flags)
{
    DebugFormat(DEBUG_STREAM_PAF,
        "%s: len=%u, amt=%u, seq=%u, cur=%u, pos=%u, fpt=%u, tot=%u, paf=%d\n",
        __func__, len, total, seq, ps->seq, ps->pos, ps->fpt, ps->tot, ps->paf);

    if ( !paf_initialized(ps) )
    {
        ps->seq = ps->pos = seq;
        ps->paf = StreamSplitter::SEARCH;
    }
    else if ( SEQ_GT(seq, ps->seq) )
    {
        // if seq jumped we have a gap.  Flush any queued data, then abort
        s5_len = total - len;

        if (s5_len)
        {
            ps->fpt = 0;
            return paf_flush(ss, ps, FT_MAX, flags);
        }
        *flags = 0;
        return -1;
    }
    else if ( SEQ_LEQ(seq + len, ps->seq) )
    {
        return -1;
    }
    else if ( SEQ_LT(seq, ps->seq) )
    {
        uint32_t shift = ps->seq - seq;
        data += shift;
        len -= shift;
    }
    ps->seq += len;

    prep_calls++;
    prep_bytes += len;

    s5_idx = total - len;

    // if 'total' is greater than the maximum paf_max AND 'total' is greater
    // than paf_max bytes + fuzz (i.e. after we have finished analyzing the
    // current segment, total bytes analyzed will be greater than the
    // configured (fuzz + paf_max) == (ss->max() + fuzz), we must ensure a flush
    // occurs at the paf_max byte.  So, we manually set the data's length and
    // total queued bytes (s5_len) to guarantee that at most paf_max bytes will
    // be analyzed and flushed since the last flush point.  It should also be
    // noted that we perform the check here rather in in paf_flush() to
    // avoid scanning the same data twice. The first scan would analyze the 
    // entire segment and the second scan would analyze this segments
    // unflushed data.
    uint16_t fuzz = 0; // FIXIT-L PAF add a little zippedy-do-dah

    if ( total >= MAX_PAF_MAX && total > ss->max(ssn) + fuzz )
    {
        s5_len = MAX_PAF_MAX + fuzz;
        len = len + s5_len - total;
    }
    else
    {
        s5_len = total;
    }

    do
    {
        FlushType ft = FT_NOP;
        uint32_t idx = s5_idx;
        uint32_t shift;
        int32_t fp;

        bool cont = paf_eval(ss, ps, ssn, *flags, data, len, &ft);

        if ( ft != FT_NOP )
        {
            fp = paf_flush(ss, ps, ft, flags);
            paf_jump(ps, fp);
            return fp;
        }
        if ( !cont )
            break;

        if ( s5_idx > idx )
        {
            shift = s5_idx - idx;
            if ( shift > len )
                shift = len;
            data += shift;
            len -= shift;
        }
    }
    while ( 1 );

    if ( ps->paf == StreamSplitter::ABORT )
        *flags = 0;

    else if ( (ps->paf != StreamSplitter::FLUSH) && (s5_len > ss->max(ssn)+fuzz) )
    {
        uint32_t fp = paf_flush(ss, ps, FT_MAX, flags);
        paf_jump(ps, fp);
        return fp;
    }
    return -1;
}

