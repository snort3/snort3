//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "paf.h"

#include "protocols/packet.h"

using namespace snort;

//--------------------------------------------------------------------
// private state
//--------------------------------------------------------------------

enum FlushType
{
    FT_NOP,  // no flush
    FT_SFP,  // abort paf
    FT_PAF,  // flush to paf pt when len >= paf
    FT_LIMIT,  // flush to paf pt, don't update flags
    FT_MAX   // flush len when len >= max
};

struct PafAux
{
    FlushType ft;
    uint32_t len;  // total bytes queued
    uint32_t idx;  // offset from start of queued bytes
};

#define PAF_LIMIT_FUZZ 1500

// 255 is max pseudo-random flush point; eth mtu ensures that maximum flushes
// are not trimmed which throws off the tracking total in stream5_paf.c
// max paf max = max datagram - eth mtu - 255 = 63780
#define MAX_PAF_MAX (65535 -  PAF_LIMIT_FUZZ - 255)

//--------------------------------------------------------------------

static uint32_t paf_flush (PAF_State* ps, PafAux& px, uint32_t* flags)
{
    uint32_t at = 0;
    *flags &= ~(PKT_PDU_HEAD | PKT_PDU_TAIL);

    switch ( px.ft )
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
        if (ps->fpt > px.len)
        {
            at = px.len;
            ps->fpt -= px.len;
        }
        else
        {
            at = ps->fpt;
            ps->fpt = px.len - ps->fpt; // number of characters scanned but not flushing
        }
        break;

    // use of px.len is suboptimal here because the actual amount
    // flushed is determined later and can differ in certain cases
    // such as exceeding s5_pkt->max_dsize.  the actual amount
    // flushed would ideally be applied to ps->fpt later.  for
    // now we try to circumvent such cases so we track correctly.
    //
    // FIXIT-L max_dsize should no longer be exceeded since it excludes headers.
    case FT_MAX:
        at = px.len;
        if ( ps->fpt > px.len )
            ps->fpt -= px.len;
        else
            ps->fpt = 0;
        break;
    }

    if ( !at || !px.len )
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
    StreamSplitter* ss, PAF_State* ps, PafAux& px, Flow* ssn,
    const uint8_t* data, uint32_t len, uint32_t flags)
{
    ps->fpt = 0;
    ps->paf = ss->scan(ssn, data, len, flags, &ps->fpt);

    if ( ps->paf == StreamSplitter::ABORT )
        return false;

    if ( ps->paf != StreamSplitter::SEARCH )
    {
        ps->fpt += px.idx;

        if ( ps->fpt <= px.len )
        {
            px.idx = ps->fpt;
            return true;
        }
    }
    px.idx = px.len;
    return false;
}

//--------------------------------------------------------------------

static inline bool paf_eval (
    StreamSplitter* ss, PAF_State* ps, PafAux& px, Flow* ssn,
    uint32_t flags, const uint8_t* data, uint32_t len)
{
    uint16_t fuzz = 0; // FIXIT-L PAF add a little zippedy-do-dah

    switch ( ps->paf )
    {
    case StreamSplitter::SEARCH:
        if ( px.len > px.idx )
        {
            return paf_callback(ss, ps, px, ssn, data, len, flags);
        }
        return false;

    case StreamSplitter::FLUSH:
        if ( px.len >= ps->fpt )
        {
            px.ft = FT_PAF;
            ps->paf = StreamSplitter::SEARCH;
            return true;
        }
        if ( px.len >= ss->max(ssn) + fuzz )
        {
            px.ft = FT_MAX;
            return false;
        }
        return false;

    case StreamSplitter::LIMIT:
        // if we are within PAF_LIMIT_FUZZ character of paf_max ...
        if ( px.len + PAF_LIMIT_FUZZ >= ss->max(ssn) + fuzz)
        {
            px.ft = FT_LIMIT;
            ps->paf = StreamSplitter::LIMITED;
            return false;
        }
        ps->paf = StreamSplitter::SEARCH;
        return false;

    case StreamSplitter::SKIP:
        if ( px.len > ps->fpt )
        {
            if ( ps->fpt > px.idx )
            {
                uint32_t delta = ps->fpt - px.idx;
                if ( delta > len )
                    return false;
                data += delta;
                len -= delta;
            }
            px.idx = ps->fpt;
            return paf_callback(ss, ps, px, ssn, data, len, flags);
        }
        return false;

    case StreamSplitter::LIMITED:
        // increment position by previously scanned bytes. set in paf_flush
        ps->paf = StreamSplitter::SEARCH;
        px.idx += ps->fpt;
        ps->fpt = 0;
        return true;

    default:
        // StreamSplitter::ABORT || StreamSplitter::START
        break;
    }

    px.ft = FT_SFP;
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
    PafAux px;

    if ( !paf_initialized(ps) )
    {
        ps->seq = ps->pos = seq;
        ps->paf = StreamSplitter::SEARCH;
    }
    else if ( SEQ_GT(seq, ps->seq) )
    {
        // if seq jumped we have a gap.  Flush any queued data, then abort
        px.len = total - len;

        if ( px.len )
        {
            ps->fpt = 0;
            px.ft = FT_MAX;
            return paf_flush(ps, px, flags);
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

    px.idx = total - len;

    // if 'total' is greater than the maximum paf_max AND 'total' is greater
    // than paf_max bytes + fuzz (i.e. after we have finished analyzing the
    // current segment, total bytes analyzed will be greater than the
    // configured (fuzz + paf_max) == (ss->max() + fuzz), we must ensure a flush
    // occurs at the paf_max byte.  So, we manually set the data's length and
    // total queued bytes (px.len) to guarantee that at most paf_max bytes will
    // be analyzed and flushed since the last flush point.  It should also be
    // noted that we perform the check here rather in in paf_flush() to
    // avoid scanning the same data twice. The first scan would analyze the
    // entire segment and the second scan would analyze this segments
    // unflushed data.
    uint16_t fuzz = 0; // FIXIT-L PAF add a little zippedy-do-dah

    if ( total >= MAX_PAF_MAX && total > ss->max(ssn) + fuzz )
    {
        px.len = MAX_PAF_MAX + fuzz;
        len = len + px.len - total;
    }
    else
    {
        px.len = total;
    }

    do
    {
        px.ft = FT_NOP;
        uint32_t idx = px.idx;

        bool cont = paf_eval(ss, ps, px, ssn, *flags, data, len);

        if ( px.ft != FT_NOP )
        {
            int32_t fp = paf_flush(ps, px, flags);
            paf_jump(ps, fp);
            return fp;
        }
        if ( !cont )
            break;

        if ( px.idx > idx )
        {
            uint32_t shift = px.idx - idx;
            if ( shift > len )
                shift = len;
            data += shift;
            len -= shift;
        }
    }
    while ( true );

    if ( ps->paf == StreamSplitter::ABORT )
        *flags = 0;

    else if ( (ps->paf != StreamSplitter::FLUSH) && (px.len > ss->max(ssn)+fuzz) )
    {
        px.ft = FT_MAX;
        uint32_t fp = paf_flush(ps, px, flags);
        paf_jump(ps, fp);
        return fp;
    }
    return -1;
}

