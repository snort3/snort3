//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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

// latency_timer.h author Joel Cornett <jocornet@cisco.com>

#ifndef LATENCY_TIMER_H
#define LATENCY_TIMER_H

#include "time/stopwatch.h"

template<typename Clock>
class LatencyTimer
{
public:
    using duration = typename Clock::duration;

    LatencyTimer(duration d) :
        max_time(d)
    { sw.start(); }

    duration elapsed() const
    { return sw.get(); }

    bool timed_out() const
    { return (max_time > CLOCK_ZERO) && (elapsed() > max_time); }

private:
    duration max_time;
    Stopwatch<Clock> sw;
};

#endif
