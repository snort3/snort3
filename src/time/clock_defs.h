//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// clock_defs.h author Joel Cornett <jocornet@cisco.com>

#ifndef CLOCK_DEFS_H
#define CLOCK_DEFS_H

#ifdef USE_TSC_CLOCK
#include "time/tsc_clock.h"
using SnortClock = TscClock;

#else
#include <chrono>
using hr_clock = std::chrono::high_resolution_clock;
using SnortClock = hr_clock;
inline long clock_scale() { return 1; }
#endif

using hr_duration = SnortClock::duration;
using hr_time = SnortClock::time_point;

inline constexpr hr_duration operator "" _ticks (unsigned long long int v)
{ return hr_duration(v); }

template<typename Clock,
    typename Duration = typename Clock::duration,
    typename TimePoint = typename Clock::time_point,
    typename Rep = typename Clock::rep>
struct ClockTraits
{
    using duration = Duration;
    using time_point = TimePoint;
    using rep = Rep;
};

inline long clock_usecs(long ticks)
{ return ticks / clock_scale(); }

inline long clock_ticks(long usecs)
{ return usecs * clock_scale(); }

#endif
