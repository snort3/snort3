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
// s5 protocol aware flushing stuff
//
// @file    stream_paf.h
// @author  Russ Combs <rcombs@sourcefire.com>
//--------------------------------------------------------------------

#ifndef STREAM5_PAF_H
#define STREAM5_PAF_H

#include <stdint.h>
#include "snort_types.h"
#include "stream/stream_api.h"
#include "stream/stream_splitter.h"

struct SnortConfig;

void* s5_paf_new(unsigned max);     // create new paf config (per policy)
void s5_paf_delete(void*);  // free config

struct PAF_State     // per session direction
{
    uint32_t seq;    // stream cursor
    uint32_t pos;    // last flush position

    uint32_t fpt;    // current flush point
    uint32_t tot;    // total bytes flushed

    StreamSplitter::Status paf;  // current scan state
};

void s5_paf_setup(PAF_State*);  // called at session start
void s5_paf_clear(PAF_State*);  // called at session end

static inline uint32_t s5_paf_position (PAF_State* ps)
{
    return ps->seq;
}

static inline uint32_t s5_paf_initialized (PAF_State* ps)
{
    return ( ps->paf != StreamSplitter::START );
}

static inline uint32_t s5_paf_active (PAF_State* ps)
{
    return ( ps->paf != StreamSplitter::ABORT );
}

// called on each in order segment
uint32_t s5_paf_check(
    StreamSplitter* paf_config, PAF_State*, Flow* ssn,
    const uint8_t* data, uint32_t len, uint32_t total,
    uint32_t seq, uint16_t port, uint32_t* flags);

#endif

