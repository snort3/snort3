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
// bitop_test.cc author Joel Cornett <joel.cornett@gmail.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/snort_catch.h"

#include "bitop.h"

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
        CHECK( (t_bitop_buffer_zero(bitop) == true) );
    }

    SECTION( "reset" )
    {
        bitop.get_buf_element(0) = 0xff;
        bitop.reset();

        CHECK( (t_bitop_buffer_zero(bitop) == true) );
    }

    SECTION( "set/is_set/clear" )
    {
        bitop.set(6);

        CHECK( (bitop.get_buf_element(0) == 0x02) );

        CHECK( bitop.is_set(6) );
        CHECK_FALSE( bitop.is_set(7) );

        bitop.set(7);
        bitop.clear(6);

        CHECK( bitop.get_buf_element(0) == 0x01 );
    }

    SECTION( "size" )
    {
        CHECK( (bitop.size() == 24) );
    }
}
