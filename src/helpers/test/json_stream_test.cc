//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// json_stream_test.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sstream>

#include "catch/catch.hpp"

#include "../json_stream.h"

TEST_CASE("basic", "[json_stream]")
{
    std::ostringstream ss;
    JsonStream js(ss);

    SECTION("empty body")
    {
        js.open();
        js.close();
        CHECK(ss.str() == "{  }\n");
    }

    SECTION("empty array")
    {
        js.open_array("a");
        js.close_array();
        const char* x = R"-("a": [  ])-";
        CHECK(ss.str() == x);
    }

    SECTION("int")
    {
        js.put("i", 0);
        const char* x = R"-("i": 0)-";
        CHECK(ss.str() == x);
    }

    SECTION("string")
    {
        js.put("s", "yo");
        const char* x = R"-("s": "yo")-";
        CHECK(ss.str() == x);
    }

    SECTION("empty string")
    {
        std::string mt;
        js.put("s", mt);
        CHECK(ss.str() == "");
    }

    SECTION("int item")
    {
        js.put(nullptr, 1);
        CHECK(ss.str() == "1");
    }

    SECTION("string item")
    {
        js.put(nullptr, "it");
        const char* x = R"-("it")-";
        CHECK(ss.str() == x);
    }

    SECTION("embedded quotes")
    {
        const char* s = R"-(content:"foo";)-";
        const char* x = R"-("content:\"foo\";")-";
        js.put(nullptr, s);
        CHECK(ss.str() == x);
    }

    SECTION("int list")
    {
        js.put("i", 2);
        js.put("j", 3);
        const char* x = R"-("i": 2, "j": 3)-";
        CHECK(ss.str() == x);
    }

    SECTION("string list")
    {
        js.put("s", "alpha");
        js.put("t", "beta");
        js.put("u", "gamma");
        const char* x = R"-("s": "alpha", "t": "beta", "u": "gamma")-";
        CHECK(ss.str() == x);
    }

    SECTION("array list")
    {
        js.open();
        js.open_array("m");
        js.close_array();
        js.open_array("n");
        js.close_array();
        js.close();
        const char* x = R"-({ "m": [  ], "n": [  ] })-" "\n";
        CHECK(ss.str() == x);
    }

    SECTION("int array")
    {
        js.open();
        js.open_array("k");
        js.put(nullptr, 4);
        js.put(nullptr, 5);
        js.put(nullptr, 6);
        js.close_array();
        js.close();
        const char* x = R"-({ "k": [ 4, 5, 6 ] })-" "\n";
        CHECK(ss.str() == x);
    }

    SECTION("string array")
    {
        js.open();
        js.open_array("v");
        js.put(nullptr, "long");
        js.put(nullptr, "road");
        js.close_array();
        js.close();
        const char* x = R"-({ "v": [ "long", "road" ] })-" "\n";
        CHECK(ss.str() == x);
    }

    SECTION("array list")
    {
        js.open();
        js.open_array("m");
        js.close_array();
        js.open_array("n");
        js.close_array();
        js.close();
        const char* x = R"-({ "m": [  ], "n": [  ] })-" "\n";
        CHECK(ss.str() == x);
    }

    SECTION("int array int")
    {
        js.open();
        js.put("a", 7);
        js.open_array("m");
        js.close_array();
        js.put("b", 8);
        js.close();
        const char* x = R"-({ "a": 7, "m": [  ], "b": 8 })-" "\n";
        CHECK(ss.str() == x);
    }

    SECTION("string array string")
    {
        js.open();
        js.put("c", "Snort");
        js.open_array("n");
        js.close_array();
        js.put("d", "++");
        js.close();
        const char* x = R"-({ "c": "Snort", "n": [  ], "d": "++" })-" "\n";
        CHECK(ss.str() == x);
    }
}

