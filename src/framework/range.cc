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
// range.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/range.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;
using namespace std;

//--------------------------------------------------------------------------
// private parsing methods
//--------------------------------------------------------------------------

static bool get_tokens(const char* s, string& low, string& ops, string& hi)
{
    unsigned state = 0;

    while ( *s )
    {
        switch ( state )
        {
        case 0:  // looking for low or ops
            if ( strchr("+-x", *s) or isxdigit(*s) )
            {
                low += *s;
                state = 1;
            }
            else if ( strchr("=!<>", *s) )
            {
                ops += *s;
                state = 2;
            }
            else if ( *s != ' ' )
                return false;
            break;
        case 1:  // accumulating low
            if ( *s == 'x' or isxdigit(*s) )
            {
                low += *s;
            }
            else if ( strchr("=!<>", *s) )
            {
                ops += *s;
                state = 2;
            }
            else if ( *s != ' ' )
                return false;
            break;
        case 2:  // accumulating ops
            if ( strchr("+-x", *s) or isxdigit(*s) )
            {
                hi += *s;
                state = 4;
            }
            else if ( strchr("=!<>", *s) )
            {
                ops += *s;
            }
            else if ( *s == ' ' )
                state = 3;
            else
                return false;
            break;
        case 3:  // looking for hi
            if ( strchr("+-x", *s) or isxdigit(*s) )
            {
                hi += *s;
                state = 4;
            }
            else
                return false;
            break;
        case 4:  // accumulating hi
            if ( *s == 'x' or isxdigit(*s) )
            {
                hi += *s;
            }
            else if ( *s != ' ' )
                return false;
            break;
        }
        ++s;
    }
    return true;
}

static bool get_op(const string& s, RangeCheck::Op& op)
{
    if ( s.empty() or s == "=" )
        op = RangeCheck::EQ;

    else if ( s == "!" )
        op = RangeCheck::NOT;

    else if ( s == "<" )
        op = RangeCheck::LT;

    else if ( s == ">" )
        op = RangeCheck::GT;

    else if ( s == "!=" )
        op = RangeCheck::NOT;

    else if ( s == "<=" )
        op = RangeCheck::LE;

    else if ( s == ">=" )
        op = RangeCheck::GE;

    else if ( s == "<>" )
        op = RangeCheck::LG;

    else if ( s == "<=>" )
        op = RangeCheck::LEG;

    else
        return false;

    return true;
}

static bool get_num(const string& s, long& num)
{
    if ( s.empty() )
    {
        num = 0;
        return true;
    }
    errno = 0;
    char* end = nullptr;
    num = strtol(s.c_str(), &end, 0);

    return !errno and !*end;
}

static bool valid(RangeCheck::Op op, bool low, bool hi)
{
    if ( op == RangeCheck::EQ )
        return (low and !hi)or (hi and !low);

    else if ( op == RangeCheck::LG or op == RangeCheck::LEG )
        return low and hi;

    return !low and hi;
}

//--------------------------------------------------------------------------
// public methods
//--------------------------------------------------------------------------

void RangeCheck::init()
{
    op = MAX;
    min = max = 0;
}

bool RangeCheck::is_set() const
{
    return (op != MAX);
}

bool RangeCheck::operator==(const RangeCheck& rhs) const
{
    return (op == rhs.op)and (min == rhs.min) and (max == rhs.max);
}

bool RangeCheck::parse(const char* s)
{
    string low, ops, hi;

    if ( !get_tokens(s, low, ops, hi) )
        return false;

    if ( !get_op(ops, op) )
        return false;

    if ( !get_num(low, min) )
        return false;

    if ( !get_num(hi, max) )
        return false;

    if ( !valid(op, !low.empty(), !hi.empty()) )
        return false;

    if ( op == EQ and hi.empty() )
    {
        if ( !ops.empty() )
            return false;

        max = min;
        min = 0;
    }
    else if ( op == GT or op == GE )
    {
        min = max;
        max = 0;
    }

    if ( (op == LG or op == LEG) and (min > max) )
        return false;

    return true;
}

bool RangeCheck::eval(long c) const
{
    switch ( op )
    {
    case EQ:
        return ( c == max );

    case NOT:
        return ( c != max );

    case LT:
        return ( c < max );

    case LE:
        return ( c <= max );

    case GT:
        return ( c > min );

    case GE:
        return ( c >= min );

    case LG:
        return ( min < c and c < max );

    case LEG:
        return ( min <= c and c <= max );

    default:
        break;
    }
    return false;
}

bool RangeCheck::validate(const char* s, const char* r)
{
    if ( !parse(s) )
        return false;
    if ( !r )
        return true;

    // check that min and max are within r
    // require no leading or trailing whitespace
    // and either # | #: | :# | #:#
    // where # is a valid pos or neg dec, hex, or octal number
    long v_min, v_max;

    if ( op == LG or op == LEG )
    {
        v_min = min;
        v_max = max;
    }
    else if ( op == GT or op == GE )
    {
        v_min = v_max = min;
    }
    else
    {
        v_min = v_max = max;
    }

    if ( *r != ':' )
    {
        long low = strtol(r, nullptr, 0);

        if ( v_min < low )
            return false;
    }

    const char* t = strchr(r, ':');

    if ( t && *++t )
    {
        long hi = strtol(t, nullptr, 0);

        if ( v_max > hi )
            return false;
    }
    return true;
}

//--------------------------------------------------------------------------
// unit tests: EQ, NOT, LT, LE, GT, GE, LG, LEG
//--------------------------------------------------------------------------

#ifdef UNIT_TEST
TEST_CASE("dflt op", "[RangeCheck]")
{
    RangeCheck rc;

    REQUIRE(rc.parse("5"));
    REQUIRE(rc.op == RangeCheck::EQ);
    REQUIRE((rc.max == 5));

    CHECK(rc.eval(5));

    CHECK(!rc.eval(4));
    CHECK(!rc.eval(6));
}

TEST_CASE("=", "[RangeCheck]")
{
    RangeCheck rc;

    REQUIRE(rc.parse("=+0x5"));
    REQUIRE(rc.op == RangeCheck::EQ);
    REQUIRE((rc.max == 5));

    CHECK(rc.eval(5));

    CHECK(!rc.eval(4));
    CHECK(!rc.eval(6));
}

TEST_CASE("!", "[RangeCheck]")
{
    RangeCheck rc;

    REQUIRE(rc.parse("!-5"));
    REQUIRE(rc.op == RangeCheck::NOT);
    REQUIRE((rc.max == -5));

    CHECK(rc.eval(-4));
    CHECK(rc.eval(-6));

    CHECK(!rc.eval(-5));
}

TEST_CASE("!=", "[RangeCheck]")
{
    RangeCheck rc;

    REQUIRE(rc.parse("!=5"));
    REQUIRE(rc.op == RangeCheck::NOT);
    REQUIRE((rc.max == 5));

    CHECK(rc.eval(4));
    CHECK(rc.eval(6));

    CHECK(!rc.eval(5));
}

TEST_CASE("<", "[RangeCheck]")
{
    RangeCheck rc;

    REQUIRE(rc.parse("<5"));
    REQUIRE(rc.op == RangeCheck::LT);
    REQUIRE((rc.max == 5));

    CHECK(rc.eval(4));
    CHECK(rc.eval(-1));

    CHECK(!rc.eval(5));
    CHECK(!rc.eval(6));
}

TEST_CASE("<=", "[RangeCheck]")
{
    RangeCheck rc;

    REQUIRE(rc.parse("<=5"));
    REQUIRE(rc.op == RangeCheck::LE);
    REQUIRE((rc.max == 5));

    CHECK(rc.eval(5));
    CHECK(rc.eval(-1));

    CHECK(!rc.eval(6));
    CHECK(!rc.eval(1000));
}

TEST_CASE(">", "[RangeCheck]")
{
    RangeCheck rc;

    REQUIRE(rc.parse(">5"));
    REQUIRE((rc.op == RangeCheck::GT));
    REQUIRE((rc.min == 5));

    CHECK(rc.eval(6));
    CHECK(rc.eval(10));

    CHECK(!rc.eval(5));
    CHECK(!rc.eval(-1));
}

TEST_CASE(">=", "[RangeCheck]")
{
    RangeCheck rc;

    REQUIRE(rc.parse(">=5"));
    REQUIRE((rc.op == RangeCheck::GE));
    REQUIRE((rc.min == 5));

    CHECK(rc.eval(5));
    CHECK(rc.eval(10));

    CHECK(!rc.eval(4));
    CHECK(!rc.eval(-4));
}

TEST_CASE("<>", "[RangeCheck]")
{
    RangeCheck rc;

    REQUIRE(rc.parse("0<>5"));
    REQUIRE((rc.op == RangeCheck::LG));
    REQUIRE(rc.min == 0);
    REQUIRE((rc.max == 5));

    CHECK(rc.eval(1));
    CHECK(rc.eval(4));

    CHECK(!rc.eval(-1));
    CHECK(!rc.eval(0));
    CHECK(!rc.eval(5));
    CHECK(!rc.eval(6));
}

TEST_CASE("<=>", "[RangeCheck]")
{
    RangeCheck rc;

    REQUIRE(rc.parse("0<=>5"));
    REQUIRE((rc.op == RangeCheck::LEG));
    REQUIRE((rc.max == 5));

    CHECK(rc.eval(0));
    CHECK(rc.eval(1));
    CHECK(rc.eval(4));
    CHECK(rc.eval(5));

    CHECK(!rc.eval(-1));
    CHECK(!rc.eval(6));
}

TEST_CASE("parsing", "[RangeCheck]")
{
    RangeCheck rc;

    SECTION("valid ranges")
    {
        SECTION("a")
        {
            REQUIRE(rc.parse("5"));
            CHECK(rc.op == RangeCheck::EQ);
            CHECK((rc.max == 5));
        }

        SECTION("b")
        {
            REQUIRE(rc.parse(" 5 "));
            CHECK(rc.op == RangeCheck::EQ);
            CHECK((rc.max == 5));
        }

        SECTION("c")
        {
            REQUIRE(rc.parse(" ! 5 "));
            CHECK(rc.op == RangeCheck::NOT);
            CHECK((rc.max == 5));
        }

        SECTION("d")
        {
            REQUIRE(rc.parse(" != 5 "));
            CHECK(rc.op == RangeCheck::NOT);
            CHECK((rc.max == 5));
        }

        SECTION("e")
        {
            REQUIRE(rc.parse(" < 5 "));
            CHECK((rc.op == RangeCheck::LT));
            CHECK((rc.max == 5));
        }

        SECTION("f")
        {
            REQUIRE(rc.parse(" > 5 "));
            CHECK((rc.op == RangeCheck::GT));
            CHECK((rc.min == 5));
        }

        SECTION("g")
        {
            REQUIRE(rc.parse(" <= 5 "));
            CHECK((rc.op == RangeCheck::LE));
            CHECK((rc.max == 5));
        }

        SECTION("h")
        {
            REQUIRE(rc.parse(" >= 5 "));
            CHECK((rc.op == RangeCheck::GE));
            CHECK((rc.min == 5));
        }

        SECTION("i")
        {
            REQUIRE(rc.parse(" 10 <> 50 "));
            CHECK((rc.op == RangeCheck::LG));
            CHECK((rc.min == 10));
            CHECK((rc.max == 50));
        }

        SECTION("j")
        {
            REQUIRE(rc.parse(" 0x10 <=> 0x50 "));
            CHECK((rc.op == RangeCheck::LEG));
            CHECK((rc.min == 0x10));
            CHECK((rc.max == 0x50));
        }

        SECTION("k")
        {
            REQUIRE(rc.parse(" -0123 <=> 0x123 "));
            CHECK((rc.op == RangeCheck::LEG));
            CHECK((rc.min == -83));
            CHECK((rc.max == 291));
        }
    }

    SECTION("invalid ranges")
    {
        // spacey operators
        CHECK(!rc.parse(" ! = 5 "));
        CHECK(!rc.parse(" < = 5 "));
        CHECK(!rc.parse(" > = 5 "));
        CHECK(!rc.parse(" 1 < > 5 "));
        CHECK(!rc.parse(" 1 < = > 5 "));
        CHECK(!rc.parse(" < > 5 "));
        CHECK(!rc.parse(" < = > 5 "));

        // other invalids
        CHECK(!rc.parse("5x"));
        CHECK(!rc.parse("5.0"));
        CHECK(!rc.parse("5-0"));
        CHECK(!rc.parse("*5"));
        CHECK(!rc.parse("=$5"));
        CHECK(!rc.parse("=5x"));
        CHECK(!rc.parse("<<0"));
        CHECK(!rc.parse("+9223372036854775808"));
        CHECK(!rc.parse("-9223372036854775809"));
        CHECK(!rc.parse("4<>2"));
        CHECK(!rc.parse("24<=>16"));

        // backwards
        CHECK(!rc.parse(" 5 = "));
        CHECK(!rc.parse(" 5 ! "));
        CHECK(!rc.parse(" 5 != "));
        CHECK(!rc.parse(" 5 < "));
        CHECK(!rc.parse(" 5 <= "));
        CHECK(!rc.parse(" 5 > "));
        CHECK(!rc.parse(" 5 >= "));

        // missing bound
        CHECK(!rc.parse(" 1 <> "));
        CHECK(!rc.parse(" <> 5 "));
        CHECK(!rc.parse(" 1 <=> "));
        CHECK(!rc.parse(" <=> 5 "));
    }
}

TEST_CASE("validate", "[RangeCheck]")
{
    RangeCheck rc;

    REQUIRE(rc.validate("2<>4", "0:10"));
    CHECK((rc.min == 2));
    CHECK((rc.max == 4));

    // #
    CHECK(rc.validate("2<>4", "0"));
    // #:
    CHECK(rc.validate("2<>4", "1:"));
    // :#
    CHECK(rc.validate("2<>4", ":8"));
    // in hex
    CHECK(rc.validate("2<>4", "0x1:0x0A"));
    
    // invalid low
    CHECK(!rc.validate("2<>4", "3:"));
    // invalid hi
    CHECK(!rc.validate("2<>4", "1:3"));
    // invalid low and hi
    CHECK(!rc.validate("200<>400", "3:10"));
}
#endif

