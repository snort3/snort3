#include "catch/catch.hpp"
#include "catch/unit_test.h"

#include "bitop.h"

SNORT_CATCH_FORCED_INCLUSION_DEFINITION(bitop_test);

static bool t_bitop_buffer_zero(BitOp& bitop)
{
    for ( size_t i = 0; i < bitop.get_buf_size(); ++i )
        if ( bitop.get_buf_element(i) )
            return false;

    return true;
}

TEST_CASE( "bitop", "[bitop]" )
{
    BitOp bitop(24);

    SECTION( "zero-initialized" )
    {
        CHECK( t_bitop_buffer_zero(bitop) );
    }

    SECTION( "reset" )
    {
        bitop.get_buf_element(0) = 0xff;
        bitop.reset();

        CHECK( t_bitop_buffer_zero(bitop) );
    }

    SECTION( "set/is_set/clear" )
    {
        bitop.set(6);

        CHECK( bitop.get_buf_element(0) == 0x02 );

        CHECK( bitop.is_set(6) );
        CHECK_FALSE( bitop.is_set(7) );

        bitop.set(7);
        bitop.clear(6);

        CHECK( bitop.get_buf_element(0) == 0x01 );
    }

    SECTION( "size" )
    {
        CHECK( bitop.size() == 24 );
    }
}
