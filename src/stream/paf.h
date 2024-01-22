//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

//--------------------------------------------------------------------
// protocol aware flushing stuff
// paf.h author Russ Combs <rcombs@sourcefire.com>
//--------------------------------------------------------------------

#ifndef PAF_H
#define PAF_H

#include "main/snort_types.h"
#include "main/thread.h"
#include "profiler/profiler_defs.h"
#include "stream/stream_splitter.h"

namespace snort
{
struct Packet;
}

extern THREAD_LOCAL snort::ProfileStats pafPerfStats;

void* paf_new(unsigned max);     // create new paf config (per policy)
void paf_delete(void*);  // free config

struct SO_PUBLIC PAF_State     // per session direction
{
    uint32_t seq;    // stream cursor
    uint32_t pos;    // last flush position

    uint32_t fpt;    // current flush point
    uint32_t tot;    // total bytes flushed

    snort::StreamSplitter::Status paf;  // current scan state
};

SO_PUBLIC void paf_setup(PAF_State*);  // called at session start
void paf_reset(PAF_State*);  // called for do overs
void paf_clear(PAF_State*);  // called at session end

inline uint32_t paf_position (PAF_State* ps)
{
    return ps->seq;
}

SO_PUBLIC inline uint32_t paf_initialized (PAF_State* ps)
{
    return ( ps->paf != snort::StreamSplitter::START );
}

SO_PUBLIC inline void paf_initialize(PAF_State* ps, uint32_t seq)
{
    ps->seq = ps->pos = seq;
    ps->fpt = ps->tot = 0;
    ps->paf = snort::StreamSplitter::SEARCH;
}

inline uint32_t paf_active (PAF_State* ps)
{
    return ( ps->paf != snort::StreamSplitter::ABORT );
}

inline void paf_jump(PAF_State* ps, uint32_t n)
{
    ps->pos += n;
    ps->seq = ps->pos;
}

// called on each in order segment
SO_PUBLIC int32_t paf_check(snort::StreamSplitter* paf_config, PAF_State*, snort::Packet* p,
    const uint8_t* data, uint32_t len, uint32_t total, uint32_t seq, uint32_t* flags);

#endif

