#include "stopwatch.h"
#include "catch/catch.hpp"

hr_duration Stopwatch::get_delta() const
{ return hr_clock::now() - start_time; }

TEST_CASE( "stopwatch", "[stopwatch]" )
{
    Stopwatch sw;

    REQUIRE_FALSE( sw.active() );
    REQUIRE( sw.get() == 0_ticks );

    SECTION( "start" )
    {
        sw.start();

        SECTION( "sets clock to active" )
        {
            CHECK( sw.active() );
        }

        SECTION( "running elapsed time should be non-zero" )
        {
            CHECK( sw.get() > 0_ticks );
        }

        SECTION( "start on running clock has no effect" )
        {
            auto val = sw.get();
            sw.start();
            CHECK( sw.active() );
            CHECK( sw.get() > val );
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
            auto val = sw.get();
            CHECK( val == sw.get() );
        }

        SECTION( "stop on stopped clock has no effect" )
        {
            auto val = sw.get();
            sw.stop();
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
            CHECK( sw.get() == 0_ticks );
        }

        SECTION( "reset on stopped clock" )
        {
            sw.stop();
            sw.reset();
            CHECK_FALSE( sw.active() );
            CHECK( sw.get() == 0_ticks );
        }
    }

    SECTION( "cancel" )
    {
        sw.start();
        SECTION( "cancel on running clock that has no lap time" )
        {
            sw.cancel();
            CHECK_FALSE( sw.active() );
            CHECK( sw.get() == 0_ticks );
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
