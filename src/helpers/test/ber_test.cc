//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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

// ber_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/catch.hpp"

#include <cstdint>

#include "helpers/ber.h"

using namespace snort;

TEST_CASE("BerReader::read rejects length that overflows cursor position", "[ber]")
{
    const uint8_t buf[] = { 0x80, 0x84, 0xFF, 0xFF, 0xFF, 0xFF };
    Cursor c;
    c.set("test", buf, sizeof(buf));

    BerReader ber(c);
    BerElement e;

    CHECK(false == ber.read(c.start(), e));
}

TEST_CASE("BerReader::read rejects length that overflows from non-zero offset", "[ber]")
{
    // total length 0xFFFFFFFF fits at offset 0 but wraps at offset 4
    const uint8_t buf[] = { 0x31, 0x08, 0xA0, 0x06, 0x80, 0x84, 0xFF, 0xFF, 0xFF, 0xF9 };
    BerElement e;
    {
        Cursor c;
        c.set("test", buf + 4, sizeof(buf) - 4);
        BerReader ber(c);
        CHECK(true == ber.read(c.start(), e));
        CHECK(e.total_length == UINT32_MAX);
    }

    Cursor c;
    c.set("test", buf, sizeof(buf));
    c.set_pos(4);
    BerReader ber(c);
    CHECK(false == ber.read(c.start(), e));
}

TEST_CASE("BerReader::read accepts truncated element with representable length", "[ber]")
{
    const uint8_t buf[] = { 0x04, 0x05, 'a' };
    Cursor c;
    c.set("test", buf, sizeof(buf));

    BerReader ber(c);
    BerElement e;

    REQUIRE(true == ber.read(c.start(), e));
    CHECK(e.type == 0x04);
    CHECK(e.length == 5);
    CHECK(e.header_length == 2);
    CHECK(e.data == buf + 2);
}

TEST_CASE("BerReader::read_uncapped accepts length that overflows cursor position", "[ber]")
{
    const uint8_t buf[] = { 0x31, 0x08, 0xA0, 0x06, 0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 'a' };
    Cursor c;
    c.set("test", buf, sizeof(buf));
    c.set_pos(4);

    BerReader ber(c);
    BerElement e;

    REQUIRE(true == ber.read_uncapped(c.start(), e));
    CHECK(e.type == 0x04);
    CHECK(e.length == UINT32_MAX);
    CHECK(e.header_length == 6);
    CHECK(e.total_length == 6ull + UINT32_MAX);
    CHECK(e.data == buf + 10);
}

TEST_CASE("BerReader::read_uncapped rejects truncated header", "[ber]")
{
    const uint8_t buf[] = { 0x04, 0x84, 0xFF, 0xFF };
    Cursor c;
    c.set("test", buf, sizeof(buf));

    BerReader ber(c);
    BerElement e;

    CHECK(false == ber.read_uncapped(c.start(), e));
}
