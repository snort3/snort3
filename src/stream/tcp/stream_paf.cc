/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

//--------------------------------------------------------------------
// s5 stuff
//
// @file    stream_paf.c
// @author  Russ Combs <rcombs@sourcefire.com>
//--------------------------------------------------------------------

// 255 is max pseudo-random flush point
// eth mtu ensures maximum flushes are not trimmed
// (that throws off the tracking total)
// max paf_max = IP_MAXPACKET - ETHERNET_MTU - 255 = 63780

#include "stream_paf.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "snort_types.h"
#include "snort_bounds.h"
#include "snort_debug.h"
#include "snort.h"
#include "stream/stream_api.h"
#include "stream/stream.h"
//#include "stream5/stream_tcp.h"
#include "target_based/sftarget_protocol_reference.h"

//--------------------------------------------------------------------
// private state
//--------------------------------------------------------------------

typedef enum {
    FT_NOP,  // no flush
    FT_SFP,  // abort paf
    FT_PAF,  // flush to paf pt when len >= paf
    FT_MAX   // flush len when len >= mfp
} FlushType;

typedef struct {
    uint8_t cb_mask;
    uint8_t auto_on;
} PAF_Map;

struct PAF_Config
{
    uint32_t mfp;

    uint32_t prep_calls;
    uint32_t prep_bytes;
};

static PAF_Map service_map[MAX_PROTOCOL_ORDINAL][2];

// s5_len and s5_idx are used only during the
// lifetime of s5_paf_check()
// FIXIT these thread local should be moved into thread context
static THREAD_LOCAL uint32_t s5_len;  // total bytes queued
static THREAD_LOCAL uint32_t s5_idx;  // offset from start of queued bytes

//--------------------------------------------------------------------

static uint32_t s5_paf_flush (
    PAF_Config*, PAF_State* ps, FlushType ft, uint32_t* flags)
{
    uint32_t at = 0;
    *flags &= ~(PKT_PDU_HEAD | PKT_PDU_TAIL);

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
       "%s: type=%d, fpt=%u, len=%u, tot=%u\n",
        __FUNCTION__, ft, ps->fpt, s5_len, ps->tot);)

    switch ( ft )
    {
    case FT_NOP:
        return 0;

    case FT_SFP:
        *flags = 0;
        return 0;

    case FT_PAF:
        at = ps->fpt;
        *flags |= PKT_PDU_TAIL;
        break;

    // use of s5_len is suboptimal here because the actual amount
    // flushed is determined later and can differ in certain cases
    // such as exceeding s5_pkt->max_dsize.  the actual amount
    // flushed would ideally be applied to ps->fpt later.  for
    // now we try to circumvent such cases so we track correctly.
    case FT_MAX:
        at = s5_len;
        if ( ps->fpt > s5_len )
            ps->fpt -= s5_len;
        else
            ps->fpt = 0;
        break;
    }

    if ( !at || !s5_len )
        return 0;

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

static bool s5_paf_callback (
    PAF_State* ps, Flow* ssn,
    const uint8_t* data, uint32_t len, uint32_t flags)
{
    PAF_Status paf = PAF_ABORT;
    uint8_t mask = ps->cb_mask;
    bool update = false;
    int i = 0;

    while ( mask )
    {
        uint8_t bit = (1<<i);
        if ( bit & mask )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
                "%s: mask=%d, i=%u\n", __FUNCTION__, mask, i);)

            PAF_Callback cb = stream.get_paf_callback(i);
            paf = cb(ssn, &ps->user, data, len, flags, &ps->fpt);

            if ( paf == PAF_ABORT )
            {
                // this one bailed out
                ps->cb_mask ^= bit;
            }
            else if ( paf != PAF_SEARCH )
            {
                // this one selected
                ps->cb_mask = bit;
                update = true;
                break;
            }
            mask ^= bit;
        }
        if ( ++i == MAX_PAF_CB )
            break;
    }
    if ( !ps->cb_mask )
    {
        ps->paf = PAF_ABORT;
        update = true;
    }
    else if ( paf != PAF_ABORT )
    {
        ps->paf = paf;
    }
    if ( update )
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

static inline bool s5_paf_eval (
    PAF_Config* pc, PAF_State* ps, Flow* ssn,
    uint16_t, uint32_t flags, uint32_t fuzz,
    const uint8_t* data, uint32_t len, FlushType* ft)
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
        "%s: paf=%d, idx=%u, len=%u, fpt=%u\n",
        __FUNCTION__, ps->paf, s5_idx, s5_len, ps->fpt);)

    switch ( ps->paf )
    {
    case PAF_SEARCH:
        if ( s5_len > s5_idx )
        {
            return s5_paf_callback(ps, ssn, data, len, flags);
        }
        return false;

    case PAF_FLUSH:
        if ( s5_len >= ps->fpt )
        {
            *ft = FT_PAF;
            ps->paf = PAF_SEARCH;
            return true;
        }
        if ( s5_len >= pc->mfp + fuzz )
        {
            *ft = FT_MAX;
            return false;
        }
        return false;

    case PAF_SKIP:
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
            return s5_paf_callback(ps, ssn, data, len, flags);
        }
        return false;

    default:
        // PAF_ABORT || PAF_START
        break;
    }

    *ft = FT_SFP;
    return false;
}

//--------------------------------------------------------------------
// public stuff
//--------------------------------------------------------------------

void s5_paf_setup (PAF_State* ps, uint8_t mask)
{
    // this is already cleared when instantiated
    //memset(ps, 0, sizeof(*ps));
    ps->paf = PAF_START;
    ps->cb_mask = mask;
}

void s5_paf_clear (PAF_State* ps)
{
    // either require pp to manage in other session state
    // or provide user free func?
    if ( ps->user )
    {
        free(ps->user);
        ps->user = NULL;
    }
    ps->paf = PAF_ABORT;
}

//--------------------------------------------------------------------

uint32_t s5_paf_check (
    void* pv, PAF_State* ps, Flow* ssn,
    const uint8_t* data, uint32_t len, uint32_t total,
    uint32_t seq, uint16_t port, uint32_t* flags, uint32_t fuzz)
{
    PAF_Config* pc = (PAF_Config*)pv;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
        "%s: len=%u, amt=%u, seq=%u, cur=%u, pos=%u, fpt=%u, tot=%u, paf=%d\n",
        __FUNCTION__, len, total, seq, ps->seq, ps->pos, ps->fpt, ps->tot, ps->paf);)

    if ( !s5_paf_initialized(ps) )
    {
        ps->seq = ps->pos = seq;
        ps->paf = PAF_SEARCH;
    }
    else if ( SEQ_GT(seq, ps->seq) )
    {
        // if seq jumped we have a gap, so abort paf
        *flags = 0;
        return 0;
    }
    else if ( SEQ_LEQ(seq + len, ps->seq) )
    {
        return 0;
    }
    else if ( SEQ_LT(seq, ps->seq) )
    {
        uint32_t shift = ps->seq - seq;
        data += shift;
        len -= shift;
    }
    ps->seq += len;

    pc->prep_calls++;
    pc->prep_bytes += len;

    s5_len = total;
    s5_idx = total - len;

    do {
        FlushType ft = FT_NOP;
        uint32_t idx = s5_idx;
        uint32_t shift, fp;

        bool cont = s5_paf_eval(pc, ps, ssn, port, *flags, fuzz, data, len, &ft);

        if ( ft != FT_NOP )
        {
            fp = s5_paf_flush(pc, ps, ft, flags);

            ps->pos += fp;
            ps->seq = ps->pos;

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

    } while ( 1 );

    if ( (ps->paf != PAF_FLUSH) && (s5_len > pc->mfp+fuzz) )
    {
        uint32_t fp = s5_paf_flush(pc, ps, FT_MAX, flags);

        ps->pos += fp;
        ps->seq = ps->pos;

        return fp;
    }
    return 0;
}

//--------------------------------------------------------------------
// service registration foo

bool s5_paf_register_service (
    SnortConfig*,uint16_t service, bool c2s, PAF_Callback cb, bool auto_on)
{
    int dir = c2s ? 1 : 0;
    int i = stream.set_paf_callback(cb);

    if ( i < 0 )
        return false;

    service_map[service][dir].cb_mask |= (1<<i);

    if ( !service_map[service][dir].auto_on )
        service_map[service][dir].auto_on = (uint8_t)auto_on;

    return true;
}

uint8_t s5_paf_service_registration (uint16_t service, bool c2s, bool flush)
{
    PAF_Map* pm = service_map[service] + (c2s?1:0);

    if ( !pm->cb_mask )
        return 0;

    if ( pm->auto_on || flush )
        return pm->cb_mask;

    return 0;
}

//--------------------------------------------------------------------

void* s5_paf_new (unsigned max)
{
    PAF_Config* pc = (PAF_Config*)SnortAlloc(sizeof(*pc));
    assert( pc );

    pc->mfp = max;

    if ( !pc->mfp )
        // this ensures max < IP_MAXPACKET
        pc->mfp = (65535 - 255);

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
        "%s: mfp=%u\n",
        __FUNCTION__, pc->mfp);)

    return pc;
}

void s5_paf_delete (void* pv)
{
    PAF_Config* pc = (PAF_Config*)pv;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
        "%s: prep=%u/%u\n",  __FUNCTION__,
        pc->prep_calls, pc->prep_bytes);)

    free(pc);
}

