//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "catch/catch.hpp"

#include "../bitop.h"

static unsigned num_set(const BitOp& bitop, size_t max)
{
    unsigned c = 0;

    for ( size_t i = 0; i < max; ++i )
    {
        if ( bitop.is_set(i) )
            c++;
    }
    return c;
}

static bool is_clear(const BitOp& bitop, size_t max)
{ return num_set(bitop, max) == 0; }

TEST_CASE( "bitop", "[bitop]" )
{
    const size_t max = 16;
    BitOp bitop(max);

    SECTION( "zero-initialized" )
    {
        CHECK( (is_clear(bitop, max) == true) );
    }

    SECTION( "toggle" )
    {
        const size_t bit = 7;

        bitop.set(bit);
        CHECK(true == bitop.is_set(bit));

        CHECK(num_set(bitop, max) == 1);

        bitop.clear(bit);
        CHECK(false == bitop.is_set(bit));

        CHECK( (is_clear(bitop, max) == true) );
    }

    SECTION( "over size" )
    {
        const size_t j = max / 2;
        const size_t k = max + 2;

        bitop.set(j);
        CHECK(true == bitop.is_set(j));

        CHECK(false == bitop.is_set(k));

        bitop.set(k);
        CHECK(true == bitop.is_set(k));

        CHECK(num_set(bitop, k + 2) == 2);
        CHECK(true == bitop.is_set(j));

        bitop.clear(k);
        CHECK(false == bitop.is_set(k));

        CHECK(true == bitop.is_set(j));
        bitop.clear(j);

        CHECK(true == is_clear(bitop, k + 2));
    }
}

