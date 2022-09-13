//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
// parse_uitls.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "parse_utils.h"

#include <cassert>
#include <cstring>

#include "log/messages.h"
#include "utils/util_cstring.h"

using namespace snort;
using namespace std;

static inline int xton(int c)
{
    if ( isdigit(c) )
        return c - '0';

    if ( isupper(c) )
        return c - 'A' + 10;

    return c - 'a' + 10;
}

bool parse_byte_code(const char* in, bool& negate, std::string& out)
{
    unsigned state = 0;
    unsigned idx = 0, len = strlen(in);
    negate = false;

    uint8_t hex = 0;
    unsigned nx = 0;
    bool ok = true;

    while ( ok && (idx < len) )
    {
        char c = in[idx++];

        switch ( state )
        {
        case 0:
            if ( c == '!' )
            {
                negate = true;
                state = 1;
                break;
            }
        // fall through
        case 1:
            if ( c == '"' and in[len-1] == '"' )
            {
                --len;
                state = 2;
            }
            else if ( !isspace(c) )
                ok = false;
            break;
        case 2:
            if ( c == '|' )
            {
                hex = 0;
                nx = 0;
                state = 4;
            }
            else
                out += c;
            break;
        case 4:
            if ( c == '|' )
            {
                if ( nx )
                    out += (char)hex;
                state = 2;
            }
            else if ( isxdigit(c) )
            {
                if ( nx >= 2 )
                {
                    out += (char)hex;
                    hex = 0;
                    nx = 0;
                }
                hex = (hex << 4) + xton(c);
                nx++;
            }
            else if ( isspace(c) && nx )
            {
                out += (char)hex;
                hex = 0;
                nx = 0;
            }
            else if ( !isspace(c) )
                ok = false;
            break;
        default:
            assert(false);
        }
    }
    if ( !ok )
        ParseError("invalid byte code at %u", idx);

    return ok;
}

int parse_int(const char* data, const char* tag, int low, int high)
{
    int32_t value = 0;
    char* endptr = nullptr;

    value = SnortStrtol(data, &endptr, 10);

    if (*endptr)
    {
        ParseError("invalid '%s' format.", tag);
        return value;
    }

    if (errno == ERANGE)
    {
        ParseError("range problem on '%s' value.", tag);
        return value;
    }

    if ((value > high) || (value < low))
    {
        ParseError("'%s' must be in %d:%d, inclusive", tag, low, high);
        return value;
    }

    return value;
}

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST

#include "catch/snort_catch.h"

TEST_CASE("parse_int", "[ParseUtils]")
{
    SECTION("invalid format")
    {
        int res = parse_int("10  ", "test");

        CHECK(res == 10);
    }

    SECTION("not a number")
    {
        const char* data = "test";

        int res = parse_int(data, data);

        CHECK(res == 0);
    }

    SECTION("int overflow")
    {
        const char* data = "99999999999999999999999999999999999999999999999999";

        int res = parse_int(data, "test");

        CHECK(res == -1);
        CHECK(errno == ERANGE);
    }

    SECTION("int underflow")
    {
        const char* data = "-9999999999999999999999999999999999999999999999999";

        int res = parse_int(data, "test");

        CHECK(res == 0);
        CHECK(errno == ERANGE);
    }

    SECTION("below the limit")
    {
        int res = parse_int("1", "test", 2, 3);

        CHECK(res == 1);
    }

    SECTION("above the limit")
    {
        int res = parse_int("4", "test", 2, 3);

        CHECK(res == 4);
    }
}

#endif
