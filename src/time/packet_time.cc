//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
/**
 * @file   packet_time.c
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Tue Jun 17 17:09:59 2003
 *
 * @brief  Easily allow modules to have a gettimeofday() based on packet time
 *
 * In many modules in snort, especially the rate detectors need to
 * work based off time values.  It's very hard to reproduce time
 * constraints via pcap readbacks so we either have to throttle snort
 * or use the packet time.  I choose the latter.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet_time.h"

#include "main/thread.h"
#include "time/timersub.h"

static THREAD_LOCAL struct timeval s_recent_packet = { 0, 0 };
static THREAD_LOCAL uint32_t s_first_packet = 0;

namespace snort
{
void packet_gettimeofday(struct timeval* tv)
{
    *tv = s_recent_packet;
}

time_t packet_time()
{
    return s_recent_packet.tv_sec;
}

int64_t timersub_ms(const struct timeval* end, const struct timeval* start)
{
    if (!end)
        end = &s_recent_packet; // use recent packet time instead when end is null

    if (!start or !start->tv_sec or !end->tv_sec)
        return 0;               // can't really compare when values are not set

    struct timeval difftime;
    TIMERSUB(end, start, &difftime);
    return difftime.tv_sec*1000 + difftime.tv_usec/1000;
}
}

void packet_time_update(const struct timeval* cur_tv)
{
    if (timercmp(&s_recent_packet, cur_tv, <))
    {
        if ( !s_first_packet )
            s_first_packet = cur_tv->tv_sec;

        s_recent_packet = *cur_tv;
    }
}

uint32_t packet_first_time()
{
    return s_first_packet;
}

