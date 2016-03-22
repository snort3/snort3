//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// flush_bucket.cc author Russ Combs <rucombs@cisco.com>

#include "flush_bucket.h"

#include <assert.h>
#include <string.h>

#include <random>

#include "main/snort_config.h"
#include "protocols/packet.h"

//-------------------------------------------------------------------------
// static base members
//-------------------------------------------------------------------------

static THREAD_LOCAL FlushBucket* s_flush_bucket = nullptr;

void FlushBucket::set(unsigned sz)
{
    if ( s_flush_bucket )
        return;

    if ( sz )
        s_flush_bucket = new ConstFlushBucket(sz);

    else if ( SnortConfig::static_hash() )
        s_flush_bucket = new StaticFlushBucket;

    else
        s_flush_bucket = new RandomFlushBucket;

    assert(s_flush_bucket);
}

void FlushBucket::clear()
{
    delete s_flush_bucket;
    s_flush_bucket = nullptr;
}

uint16_t FlushBucket::get_size()
{
    return s_flush_bucket->get_next();
}

//-------------------------------------------------------------------------
// thread local data
//-------------------------------------------------------------------------

#define RAND_FLUSH_POINTS 64

static THREAD_LOCAL uint8_t flush_points[RAND_FLUSH_POINTS] =
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

//-------------------------------------------------------------------------
// sub classes
//-------------------------------------------------------------------------

StaticFlushBucket::StaticFlushBucket()
{
    idx = 0;
}

uint16_t StaticFlushBucket::get_next()
{
    if ( idx >= RAND_FLUSH_POINTS )
            idx = 0;

    return flush_points[idx++];
}

RandomFlushBucket::RandomFlushBucket()
{
    std::default_random_engine generator;
    std::uniform_int_distribution<int> distribution(128, 255);

    for ( int i = 0; i < RAND_FLUSH_POINTS; i++ )
    {
        flush_points[i] = (uint8_t)distribution(generator);
    }
}

