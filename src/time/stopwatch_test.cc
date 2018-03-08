//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// stopwatch_test.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/snort_catch.h"

#include "clock_defs.h"
#include "stopwatch.h"

namespace t_stopwatch
{

struct Clock : public ClockTraits<SnortClock>
{
    static time_point now()
    { return time; }

    static void inc(duration amount = duration(1))
    { time += amount; }

    static void reset()
    { time = Clock::time_point(Clock::duration(0)); }

    static time_point time;
};

Clock::time_point Clock::time;

} // namespace t_stopwatch

// FIXIT-L we can use a customized template for Clock to create a more deterministic unit test
TEST_CASE( "stopwatch", "[time][stopwatch]" )
{
    using namespace t_stopwatch;

    Stopwatch<Clock> sw;
    Clock::reset();

    REQUIRE_FALSE( sw.active() );
    REQUIRE( (sw.get() == 0_ticks) );

    SECTION( "start" )
    {
        sw.start();

        SECTION( "sets clock to active" )
        {
            CHECK( sw.active() );
        }

        SECTION( "running elapsed time should be non-zero" )
        {
            Clock::inc();
            CHECK( (sw.get() > 0_ticks) );
        }

        SECTION( "start on running clock has no effect" )
        {
            sw.start();
            CHECK( sw.active() );
        }
    }

    SECTION( "stop" )
    {
        sw.start();
        sw.stop();

        SECTION( "sets clock to be dead" )
        {
            CHECK_FALSE( sw.active() );
        }

        SECTION( "ticks should not increase after death" )
        {
            Clock::inc();
            auto val = sw.get();
            CHECK( val == sw.get() );
        }

        SECTION( "stop on stopped clock has no effect" )
        {
            auto val = sw.get();
            sw.stop();
            Clock::inc();
            CHECK_FALSE( sw.active() );
            CHECK( val == sw.get() );
        }
    }

    SECTION( "reset" )
    {
        sw.start();

        SECTION( "reset on running clock" )
        {
            sw.reset();
            CHECK_FALSE( sw.active() );
            CHECK( (sw.get() == 0_ticks) );
        }

        SECTION( "reset on stopped clock" )
        {
            sw.stop();
            sw.reset();
            CHECK_FALSE( sw.active() );
            CHECK( (sw.get() == 0_ticks) );
        }
    }

    SECTION( "cancel" )
    {
        sw.start();
        SECTION( "cancel on running clock that has no lap time" )
        {
            sw.cancel();
            CHECK_FALSE( sw.active() );
            CHECK( (sw.get() == 0_ticks) );
        }

        SECTION( "cancel on stopped clock that has lap time" )
        {
            sw.stop();
            auto val = sw.get();
            sw.cancel();

            CHECK_FALSE( sw.active() );
            CHECK( val == sw.get() );
        }
    }
}
