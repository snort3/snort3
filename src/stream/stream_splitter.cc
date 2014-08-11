/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// stream_splitter.cc author Russ Combs <rucombs@cisco.com>

#include "stream/stream_splitter.h"

#include <assert.h>
#include <string.h>

#include "protocols/packet.h"

static THREAD_LOCAL uint8_t pdu_buf[65536];
static THREAD_LOCAL StreamBuffer str_buf;

uint32_t StreamSplitter::max()
{ return 16384; }  // FIXIT make default configurable

const StreamBuffer* StreamSplitter::reassemble(
    Flow*, unsigned offset, const uint8_t* p,
    unsigned n, uint32_t flags, unsigned& copied)
{ 
    assert(offset + n < sizeof(pdu_buf));
    memcpy(pdu_buf+offset, p, n);
    copied = n;

    if ( flags & PKT_PDU_TAIL )
    {
        str_buf.data = pdu_buf;
        str_buf.length = offset + n;
        return &str_buf;
    }
    return nullptr;
}

AtomSplitter::AtomSplitter(bool b, uint32_t sz) : StreamSplitter(b)
{
    reset();
    // FIXIT get next random flush point unless set explicitly here
    min = sz ? sz : 192;
}

AtomSplitter::~AtomSplitter() { }

PAF_Status AtomSplitter::scan(
    Flow*, const uint8_t*, uint32_t len, uint32_t, uint32_t* fp
) {
    bytes += len;
    segs++;
    
    if ( segs >= 2 && bytes >= 192 )
    {
        *fp = len;
        return PAF_FLUSH;
    }
    return PAF_SEARCH;
}

void AtomSplitter::reset()
{
    bytes = segs = 0;
}

void AtomSplitter::update()
{
    reset();
    // FIXIT get next random flush point unless set explicitly in ctor
    //min = 192;
}

#if 0
// FIXIT PAF atom splitter must implement old-schoold flush criteria
// 2 or more segments totaling at least N bytes where N is uniform 
// over 128 to 255
//
// ideally it would be a little more flexible too

#define RAND_FLUSH_POINTS 64

static const uint32_t g_static_points[RAND_FLUSH_POINTS] =
{
    128, 217, 189, 130, 240, 221, 134, 129,
    250, 232, 141, 131, 144, 177, 201, 130,
    230, 190, 177, 142, 130, 200, 173, 129,
    250, 244, 174, 151, 201, 190, 180, 198,
    220, 201, 142, 185, 219, 129, 194, 140,
    145, 191, 197, 183, 199, 220, 231, 245,
    233, 135, 143, 158, 174, 194, 200, 180,
    201, 142, 153, 187, 173, 199, 143, 201
};

#ifndef DYNAMIC_RANDOM_FLUSH_POINTS
struct FlushPointList
{
    uint8_t    current;

    uint32_t   flush_range;
    uint32_t   flush_base;  /* Set as value - range/2 */
    /* flush_pt is split evently on either side of flush_value, within
     * the flush_range.  flush_pt can be from:
     * (flush_value - flush_range/2) to (flush_value + flush_range/2)
     *
     * For example:
     * flush_value = 192
     * flush_range = 128
     * flush_pt will vary from 128 to 256
     */
    uint32_t *flush_points;
};
#endif

static inline uint32_t GenerateFlushPoint(FlushPointList *flush_point_list)
{
    return (rand() % flush_point_list->flush_range) + flush_point_list->flush_base;
}

static void InitFlushPointList(
    FlushPointList *flush_point_list, uint32_t value, uint32_t range, int footprint)
{
    uint32_t i;
    uint32_t flush_range = range;
    uint32_t flush_base = value - range/2;

    const uint32_t cfp = footprint ? footprint : 192;

    flush_point_list->flush_range = flush_range;
    flush_point_list->flush_base = flush_base;

#ifndef DYNAMIC_RANDOM_FLUSH_POINTS
    flush_point_list->current = 0;

    flush_point_list->flush_points =
        (uint32_t*)SnortAlloc(sizeof(uint32_t) * RAND_FLUSH_POINTS);

    for (i=0;i<RAND_FLUSH_POINTS;i++)
    {
        if (snort_conf->run_flags & RUN_FLAG__STATIC_HASH)
        {
            if ( i == 0 )
                LogMessage("WARNING:  using constant flush point = %u!\n", cfp);

            flush_point_list->flush_points[i] = cfp;
        }
        else if ( !footprint )
        {
            if ( i == 0 )
                LogMessage("WARNING: using static flush points.\n");
            flush_point_list->flush_points[i] = g_static_points[i];
        }
        else
        {
            flush_point_list->flush_points[i] = GenerateFlushPoint(flush_point_list);
        }
    }
#endif
}

static inline int CheckFlushCoercion (
    Packet* p, FlushMgr* fm, uint16_t flush_factor
) {
    if ( !flush_factor )
        return 0;

    if (
        p->dsize &&
        (p->dsize < fm->last_size) &&
        (fm->last_count >= flush_factor) )
    {
        fm->last_size = 0;
        fm->last_count = 0;
        return 1;
    }
    if ( p->dsize > fm->last_size )
        fm->last_size = p->dsize;

    fm->last_count++;
    return 0;
}

static void Stream5TcpInitFlushPoints(void)
{
    int i;

    /* Seed the flushpoint random generator */
    srand( (unsigned int) sizeof(TcpSession) + (unsigned int) time(NULL) );
}
#endif

