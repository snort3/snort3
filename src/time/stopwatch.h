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
// stopwatch.h author Joel Cornett <jocornet@cisco.com>

#ifndef STOPWATCH_H
#define STOPWATCH_H

template<typename Clock>
class Stopwatch
{
public:
    using duration = typename Clock::duration;
    using time_point = typename Clock::time_point;

    Stopwatch() :
        elapsed { duration::zero() }, running { false } { }

    void start()
    {
        if ( running )
            return;

        start_time = Clock::now();
        running = true;
    }

    void stop()
    {
        if ( !running )
            return;

        elapsed += get_delta();
        running = false;
    }

    duration get() const
    {
        if ( running )
            return elapsed + get_delta();

        return elapsed;
    }

    bool active() const
    { return running; }

    void reset()
    { running = false; elapsed = duration::zero(); }

    void cancel()
    { running = false; }

private:
    duration get_delta() const
    { return Clock::now() - start_time; }

    duration elapsed;
    bool running;
    time_point start_time;
};

#endif
