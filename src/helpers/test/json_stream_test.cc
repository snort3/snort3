//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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

using namespace snort;

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

    SECTION("empty root array")
    {
        js.open_array();
        js.close_array();
        const char* x = R"-([  ])-" "\n";
        CHECK(ss.str() == x);
    }

    SECTION("empty object")
    {
        js.open();
        js.open("o");
        js.close();
        js.close();
        const char* x = R"-({ "o": {  } })-" "\n";
        CHECK(ss.str() == x);
    }

    SECTION("empty array")
    {
        js.open();
        js.open_array("a");
        js.close_array();
        js.close();
        const char* x = R"-({ "a": [  ] })-" "\n";
        CHECK(ss.str() == x);
    }

    SECTION("null")
    {
        js.put("n");
        const char* x = R"-("n": null)-";
        CHECK(ss.str() == x);
    }

    SECTION("bool true")
    {
        js.put_true("b");
        const char* x = R"-("b": true)-";
        CHECK(ss.str() == x);
    }

    SECTION("bool false")
    {
        js.put_false("b");
        const char* x = R"-("b": false)-";
        CHECK(ss.str() == x);
    }

    SECTION("int")
    {
        js.put("i", (int64_t)0);
        const char* x = R"-("i": 0)-";
        CHECK(ss.str() == x);
    }

    SECTION("real")
    {
        js.put("r", 2.5, 2);
        const char* x = R"-("r": 2.50)-";
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

    SECTION("null item")
    {
        js.put(nullptr);
        CHECK(ss.str() == "null");
    }

    SECTION("bool true item")
    {
        js.put_true(nullptr);
        CHECK(ss.str() == "true");
    }

    SECTION("bool false item")
    {
        js.put_false(nullptr);
        CHECK(ss.str() == "false");
    }

    SECTION("int item")
    {
        js.put(nullptr, 1);
        CHECK(ss.str() == "1");
    }

    SECTION("real item")
    {
        js.put(nullptr, 2.5, 2);
        CHECK(ss.str() == "2.50");
    }

    SECTION("string item")
    {
        js.put(nullptr, "it");
        const char* x = R"-("it")-";
        CHECK(ss.str() == x);
    }

    SECTION("backslash")
    {
        const char* s = R"-(content:\test\;)-";
        const char* x = R"-("content:\\test\\;")-";
        js.put(nullptr, s);
        CHECK(ss.str() == x);
    }

    SECTION("embedded quotes")
    {
        const char* s = R"-(content:"foo";)-";
        const char* x = R"-("content:\"foo\";")-";
        js.put(nullptr, s);
        CHECK(ss.str() == x);
    }

    SECTION("special characters")
    {
        const char* s = R"-(content: / " \ $ # ! @ % ^ & * ' \b\f\t\r\n . )-";
        const char* x = R"-("content: / \" \\ $ # ! @ % ^ & * ' \\b\\f\\t\\r\\n . ")-";
        js.put(nullptr, s);
        CHECK(ss.str() == x);
    }

    SECTION("null list")
    {
        js.put("i");
        js.put("j");
        const char* x = R"-("i": null, "j": null)-";
        CHECK(ss.str() == x);
    }

    SECTION("bool list")
    {
        js.put_true("i");
        js.put_false("j");
        const char* x = R"-("i": true, "j": false)-";
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

    SECTION("null array")
    {
        js.open();
        js.open_array("n");
        js.put(nullptr);
        js.put(nullptr);
        js.put(nullptr);
        js.close_array();
        js.close();
        const char* x = R"-({ "n": [ null, null, null ] })-" "\n";
        CHECK(ss.str() == x);
    }

    SECTION("bool array")
    {
        js.open();
        js.open_array("b");
        js.put_true(nullptr);
        js.put_false(nullptr);
        js.put_true(nullptr);
        js.close_array();
        js.close();
        const char* x = R"-({ "b": [ true, false, true ] })-" "\n";
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

    SECTION("real array")
    {
        js.open();
        js.open_array("r");
        js.put(nullptr, 2.556, 3);
        js.put(nullptr, 3.7778, 4);
        js.close_array();
        js.close();
        const char* x = R"-({ "r": [ 2.556, 3.7778 ] })-" "\n";
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

    SECTION("root array of objects")
    {
        js.open_array();
        js.open();
        js.close();
        js.open();
        js.close();
        js.open();
        js.close();
        js.close_array();
        const char* x = R"-([ {  }, {  }, {  } ])-" "\n";
        CHECK(ss.str() == x);
    }

    SECTION("root array of objects with nested arrays of objects")
    {
        js.open_array();
        js.open();
        js.put("i", 1);
        js.open_array("array_1");
        js.open();
        js.put("str", "Snort");
        js.close();
        js.open();
        js.put("str", "++");
        js.close();
        js.close_array();
        js.put("j", 2);
        js.close();
        js.open();
        js.put("i", 3);
        js.open_array("array_2");
        js.open();
        js.put("str", "IPS");
        js.close();
        js.open();
        js.put("str", "IDS");
        js.close();
        js.close_array();
        js.put("j", 4);
        js.close();
        js.close_array();
        const char* x = R"-([ { "i": 1, "array_1": [ { "str": "Snort" }, { "str": "++" } ],)-"
            R"-( "j": 2 }, { "i": 3, "array_2": [ { "str": "IPS" }, { "str": "IDS" } ],)-"
            R"-( "j": 4 } ])-" "\n";
        CHECK(ss.str() == x);
    }

    SECTION("root object with nested objects")
    {
        js.open();
        js.open_array("keys");
        js.put(nullptr, "name");
        js.put(nullptr, "version");
        js.close_array();
        js.open("name");
        js.put("value", "Snort");
        js.close();
        js.open("version");
        js.put("value", "3.0.0");
        js.close();
        js.close();
        const char* x = R"-({ "keys": [ "name", "version" ], "name": { "value": "Snort" },)-"
            R"-( "version": { "value": "3.0.0" } })-" "\n";
        CHECK(ss.str() == x);
    }
}

