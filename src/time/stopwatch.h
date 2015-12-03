//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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
// stopwatch.h author Joel Cornett <jocornet@cisco.com>

#ifndef STOPWATCH_H
#define STOPWATCH_H

#include <chrono>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "time/clock_defs.h"
#include "main/snort_types.h"

class Stopwatch
{
public:
    Stopwatch() :
        elapsed { hr_duration::zero() }, running { false } { }

    void start()
    {
        if ( running )
            return;

        start_time = hr_clock::now();
        running = true;
    }

    void stop()
    {
        if ( !running )
            return;

        elapsed += get_delta();
        running = false;
    }

    hr_duration get() const
    {
        if ( running )
            return elapsed + get_delta();

        return elapsed;
    }

    bool active() const
    { return running; }

    void reset()
    { running = false; elapsed = hr_duration::zero(); }

    void cancel()
    { running = false; }

private:
// Dirty, dirty hack to get Catch unit test visibility
#ifdef UNIT_TEST
    SO_PUBLIC hr_duration get_delta() const;
#else
    hr_duration get_delta() const
    { return hr_clock::now() - start_time; }
#endif

    hr_duration elapsed;
    bool running;
    hr_time start_time;
};

#endif
