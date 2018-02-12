//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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
// tsc_clock.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tsc_clock.h"

#include <ctime>

long clock_scale()
{
#ifndef USE_TSC_CLOCK
    return 1;
#else
    static long tpus = 0;  // ticks / usec

    if ( !tpus )
    {
        struct timespec one_sec = { 1, 0 };
        uint64_t start = TscClock::counter();
        nanosleep(&one_sec, nullptr);
        uint64_t end = TscClock::counter();
        tpus = (long)((end - start)/1e6);
    }
    return tpus;
#endif
}

