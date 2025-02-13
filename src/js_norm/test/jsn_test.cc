//--------------------------------------------------------------------------
// Copyright (C) 2022-2025 Cisco and/or its affiliates. All rights reserved.
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
// jsn_test.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>

#include "catch/catch.hpp"

#include "js_norm/js_norm.h"

using namespace jsn;
using namespace snort;

#ifdef CATCH_TEST_BUILD

TEST_CASE("configuration", "[JSNorm]")
{
    const void* dst = nullptr;
    size_t dst_len = 0;

    SECTION("no config passed")
    {
        JSNorm jsn(nullptr);

        const std::string src = "var";

        jsn.normalize(src.c_str(), src.size(), dst, dst_len);

        CHECK(dst == nullptr);
        CHECK(dst_len == 0);
    }

    SECTION("config passed")
    {
        JSNormConfig config;
        JSNorm jsn(&config);

        const std::string src = "var ";
        const std::string exp = "var";

        jsn.normalize(src.c_str(), src.size(), dst, dst_len);

        REQUIRE(dst != nullptr);
        REQUIRE(dst_len != 0);

        CHECK(std::string((const char*)dst, dst_len) == exp);
    }
}

TEST_CASE("normalization", "[JSNorm]")
{
    JSNormConfig config;
    JSNorm jsn(&config);

    const void* dst = nullptr;
    size_t dst_len = 0;

    SECTION("missed input")
    {
        const std::string src = "var";

        jsn.tick();
        jsn.tick();
        jsn.tick();

        jsn.normalize(src.c_str(), src.size(), dst, dst_len);

        CHECK(dst == nullptr);
        CHECK(dst_len == 0);
    }

    SECTION("data lost")
    {
        const std::string src = "var";

        jsn.tick();
        jsn.tick();

        jsn.normalize(src.c_str(), src.size(), dst, dst_len);

        CHECK(dst == nullptr);
        CHECK(dst_len == 0);
    }

    SECTION("passed")
    {
        const std::string pdu_1 = "var ";
        const std::string pdu_2 = "a = ";
        const std::string pdu_3 = "1 ;";

        // dst buffer is accumulated if no explicit flushing
        const std::string norm_pdu_1 = "var";
        const std::string norm_pdu_2 = "var var_0000=";
        const std::string norm_pdu_3 = "var var_0000=1;";

        jsn.tick();
        jsn.normalize(pdu_1.c_str(), pdu_1.size(), dst, dst_len);

        REQUIRE(dst != nullptr);
        REQUIRE(dst_len != 0);

        CHECK(std::string((const char*)dst, dst_len) == norm_pdu_1);

        jsn.tick();
        jsn.normalize(pdu_2.c_str(), pdu_2.size(), dst, dst_len);

        REQUIRE(dst != nullptr);
        REQUIRE(dst_len != 0);

        CHECK(std::string((const char*)dst, dst_len) == norm_pdu_2);

        jsn.tick();
        jsn.normalize(pdu_3.c_str(), pdu_3.size(), dst, dst_len);

        REQUIRE(dst != nullptr);
        REQUIRE(dst_len != 0);

        CHECK(std::string((const char*)dst, dst_len) == norm_pdu_3);
    }
}

TEST_CASE("non-blocking events", "[JSNorm]")
{
    REQUIRE(EventSid::EVENT__MAX_VALUE == 10);

    JSNormConfig config;
    config.ignored_ids.insert("unescape");

    JSNorm jsn(&config, false);
    const void* dst = nullptr;
    size_t dst_len = 0;

    std::string src = "'bar'";
    std::string exp = "'bar'";

    SECTION("EVENT_NEST_UNESCAPE_FUNC")
    {
        src = "unescape(unescape('foo')) ;";
        exp = "'foo';";
    }

    SECTION("EVENT_MIXED_UNESCAPE_SEQUENCE")
    {
        src = "unescape(\"\\u66%6f\\u6f\") ;";
        exp = "\"foo\";";
    }

    SECTION("EVENT_OPENING_TAG")
    {
        src = "'<script>' ;";
        exp = "'<script>';";
    }

    SECTION("EVENT_CLOSING_TAG")
    {
        JSNorm tmp_jsn(&config, true);

        std::string tmp_src = "'</script>' ;";
        std::string tmp_exp = "'</script>';";

        tmp_jsn.normalize(tmp_src.c_str(), tmp_src.size(), dst, dst_len);

        REQUIRE(dst != nullptr);
        REQUIRE(dst_len != 0);

        CHECK(std::string((const char*)dst, dst_len) == tmp_exp);
    }

    jsn.normalize(src.c_str(), src.size(), dst, dst_len);

    REQUIRE(dst != nullptr);
    REQUIRE(dst_len != 0);

    CHECK(std::string((const char*)dst, dst_len) == exp);
}

TEST_CASE("blocking events", "[JSNorm]")
{
    REQUIRE(EventSid::EVENT__MAX_VALUE == 10);

    JSNormConfig config;
    JSNorm jsn(&config, false);

    const void* dst = nullptr;
    size_t dst_len = 0;

    std::string src = "'bar'";
    std::string exp = "'bar'";

    SECTION("EVENT_CLOSING_TAG")
    {
        src = "'</script>' ;";
        exp = "'";
    }

    SECTION("EVENT_BAD_TOKEN")
    {
        src = "{)";
        exp = "{";
    }

    SECTION("EVENT_IDENTIFIER_OVERFLOW")
    {
        config.identifier_depth = 0;

        JSNorm tmp_jsn(&config, false);

        std::string tmp_src = "; a";
        std::string tmp_exp = ";";

        tmp_jsn.normalize(tmp_src.c_str(), tmp_src.size(), dst, dst_len);

        REQUIRE(dst != nullptr);
        REQUIRE(dst_len != 0);

        CHECK(std::string((const char*)dst, dst_len) == tmp_exp);
    }

    SECTION("EVENT_BRACKET_NEST_OVERFLOW")
    {
        config.max_bracket_depth = 0;

        JSNorm tmp_jsn(&config, false);

        std::string tmp_src = "; {";
        std::string tmp_exp = ";";

        tmp_jsn.normalize(tmp_src.c_str(), tmp_src.size(), dst, dst_len);

        REQUIRE(dst != nullptr);
        REQUIRE(dst_len != 0);

        CHECK(std::string((const char*)dst, dst_len) == tmp_exp);
    }

    SECTION("EVENT_SCOPE_NEST_OVERFLOW")
    {
        config.max_scope_depth = 0;

        JSNorm tmp_jsn(&config, false);

        std::string tmp_src = "; function f () {";
        std::string tmp_exp = ";function var_0000";

        tmp_jsn.normalize(tmp_src.c_str(), tmp_src.size(), dst, dst_len);

        REQUIRE(dst != nullptr);
        REQUIRE(dst_len != 0);

        CHECK(std::string((const char*)dst, dst_len) == tmp_exp);
    }

    jsn.normalize(src.c_str(), src.size(), dst, dst_len);

    REQUIRE(dst != nullptr);
    REQUIRE(dst_len != 0);

    CHECK(std::string((const char*)dst, dst_len) == exp);
}

#endif
