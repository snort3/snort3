//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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
// js_identifier_ctx_test.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/catch.hpp"

#include <cstring>
#include <iomanip>
#include <sstream>
#include <vector>

#include "js_norm/js_identifier_ctx.h"

using namespace jsn;

#define DEPTH 65536
#define SCOPE_DEPTH 256

static const std::unordered_set<std::string> s_ignored_ids { "console", "v" };
static const std::unordered_set<std::string> s_ignored_props { "watch", "w" };

TEST_CASE("JSIdentifierCtx::substitute()", "[JSIdentifierCtx]")
{
    SECTION("same name")
    {
        JSIdentifierCtx ident_ctx(DEPTH, SCOPE_DEPTH, s_ignored_ids, s_ignored_props);

        CHECK(!strcmp(ident_ctx.substitute("a", false), "var_0000"));
        CHECK(!strcmp(ident_ctx.substitute("a", false), "var_0000"));
    }
    SECTION("different names")
    {
        JSIdentifierCtx ident_ctx(DEPTH, SCOPE_DEPTH, s_ignored_ids, s_ignored_props);

        CHECK(!strcmp(ident_ctx.substitute("a", false), "var_0000"));
        CHECK(!strcmp(ident_ctx.substitute("b", false), "var_0001"));
        CHECK(!strcmp(ident_ctx.substitute("a", false), "var_0000"));
    }
    SECTION("depth reached")
    {
        JSIdentifierCtx ident_ctx(2, SCOPE_DEPTH, s_ignored_ids, s_ignored_props);

        CHECK(!strcmp(ident_ctx.substitute("a", false), "var_0000"));
        CHECK(!strcmp(ident_ctx.substitute("b", false), "var_0001"));
        CHECK(ident_ctx.substitute("c", false) == nullptr);
        CHECK(ident_ctx.substitute("d", false) == nullptr);
        CHECK(!strcmp(ident_ctx.substitute("a", false), "var_0000"));
    }
    SECTION("max names")
    {
        JSIdentifierCtx ident_ctx(DEPTH + 2, SCOPE_DEPTH, s_ignored_ids, s_ignored_props);

        std::vector<std::string> n, e;
        n.reserve(DEPTH + 2);
        e.reserve(DEPTH);

        for (int it = 0; it < DEPTH + 2; ++it)
            n.push_back("n" + std::to_string(it));

        for (int it_name = 0; it_name < DEPTH; ++it_name)
        {
            std::stringstream stream;
            stream << std::setfill ('0') << std::setw(4)
                << std::hex << it_name;
            e.push_back("var_" + stream.str());
        }

        for (int it = 0; it < DEPTH; ++it)
            CHECK(!strcmp(ident_ctx.substitute(n[it].c_str(), false), e[it].c_str()));

        CHECK(ident_ctx.substitute(n[DEPTH].c_str(), false) == nullptr);
        CHECK(ident_ctx.substitute(n[DEPTH + 1].c_str(), false) == nullptr);
    }
    SECTION("ignored identifier - single char")
    {
        JSIdentifierCtx ident_ctx(DEPTH, SCOPE_DEPTH, s_ignored_ids, s_ignored_props);

        CHECK(!strcmp(ident_ctx.substitute("v", false), "v"));
        CHECK(!strcmp(ident_ctx.substitute("v", true), "var_0000"));
        CHECK(!strcmp(ident_ctx.substitute("w", false), "var_0001"));
        CHECK(!strcmp(ident_ctx.substitute("w", true), "w"));
    }
    SECTION("ignored identifier - multiple chars")
    {
        JSIdentifierCtx ident_ctx(DEPTH, SCOPE_DEPTH, s_ignored_ids, s_ignored_props);

        CHECK(!strcmp(ident_ctx.substitute("console", false), "console"));
        CHECK(!strcmp(ident_ctx.substitute("console", true), "var_0000"));
        CHECK(!strcmp(ident_ctx.substitute("watch", false), "var_0001"));
        CHECK(!strcmp(ident_ctx.substitute("watch", true), "watch"));
    }
}

TEST_CASE("JSIdentifierCtx::is_ignored()", "[JSIdentifierCtx]")
{
    SECTION("single char identifier")
    {
        JSIdentifierCtx ident_ctx(DEPTH, SCOPE_DEPTH, s_ignored_ids, s_ignored_props);

        auto v1 = ident_ctx.substitute("v", false);
        auto v2 = ident_ctx.substitute("a", false);
        auto v3 = ident_ctx.substitute("w", false);
        auto v4 = ident_ctx.substitute("w", true);

        CHECK(true == ident_ctx.is_ignored(v1));
        CHECK(false == ident_ctx.is_ignored(v2));
        CHECK(false == ident_ctx.is_ignored(v3));
        CHECK(true == ident_ctx.is_ignored(v4));
    }
    SECTION("multiple chars identifier")
    {
        JSIdentifierCtx ident_ctx(DEPTH, SCOPE_DEPTH, s_ignored_ids, s_ignored_props);

        auto v1 = ident_ctx.substitute("console", false);
        auto v2 = ident_ctx.substitute("foo", false);
        auto v3 = ident_ctx.substitute("watch", false);
        auto v4 = ident_ctx.substitute("watch", true);

        CHECK(true == ident_ctx.is_ignored(v1));
        CHECK(false == ident_ctx.is_ignored(v2));
        CHECK(false == ident_ctx.is_ignored(v3));
        CHECK(true == ident_ctx.is_ignored(v4));
    }
}

TEST_CASE("JSIdentifierCtx::scopes", "[JSIdentifierCtx]")
{
    JSIdentifierCtx ident_ctx(DEPTH, SCOPE_DEPTH, s_ignored_ids, s_ignored_props);

    SECTION("scope stack")
    {
        CHECK(true == ident_ctx.scope_check({GLOBAL}));

        ident_ctx.scope_push(JSProgramScopeType::FUNCTION);
        ident_ctx.scope_push(JSProgramScopeType::BLOCK);
        ident_ctx.scope_push(JSProgramScopeType::BLOCK);
        CHECK(true == ident_ctx.scope_check({GLOBAL, FUNCTION, BLOCK, BLOCK}));

        CHECK(true == ident_ctx.scope_pop(JSProgramScopeType::BLOCK));
        CHECK(true == ident_ctx.scope_check({GLOBAL, FUNCTION, BLOCK}));

        ident_ctx.reset();
        CHECK(true == ident_ctx.scope_check({GLOBAL}));
    }
    SECTION("aliases")
    {
        ident_ctx.add_alias("a", "console.log");
        ident_ctx.add_alias("b", "document");
        CHECK(!strcmp(ident_ctx.alias_lookup("a"), "console.log"));
        CHECK(!strcmp(ident_ctx.alias_lookup("b"), "document"));

        REQUIRE(true == ident_ctx.scope_push(JSProgramScopeType::FUNCTION));
        ident_ctx.add_alias("a", "document");
        CHECK(!strcmp(ident_ctx.alias_lookup("a"), "document"));
        CHECK(!strcmp(ident_ctx.alias_lookup("b"), "document"));

        REQUIRE(true == ident_ctx.scope_push(JSProgramScopeType::BLOCK));
        ident_ctx.add_alias("b", "console.log");
        CHECK(!strcmp(ident_ctx.alias_lookup("b"), "console.log"));
        CHECK(!strcmp(ident_ctx.alias_lookup("a"), "document"));

        REQUIRE(true == ident_ctx.scope_pop(JSProgramScopeType::BLOCK));
        REQUIRE(true == ident_ctx.scope_pop(JSProgramScopeType::FUNCTION));
        ident_ctx.add_alias("a", "eval");
        CHECK(!strcmp(ident_ctx.alias_lookup("a"), "eval"));
        CHECK(!strcmp(ident_ctx.alias_lookup("b"), "document"));

        CHECK(ident_ctx.alias_lookup("c") == nullptr);
    }
    SECTION("scope mismatch")
    {
        CHECK(false == ident_ctx.scope_pop(JSProgramScopeType::FUNCTION));
        CHECK(true == ident_ctx.scope_check({GLOBAL}));
        CHECK(false == ident_ctx.scope_check({FUNCTION}));

        CHECK(true == ident_ctx.scope_push(JSProgramScopeType::FUNCTION));
        CHECK(true == ident_ctx.scope_check({GLOBAL, FUNCTION}));
        CHECK(false == ident_ctx.scope_pop(JSProgramScopeType::BLOCK));
        CHECK(true == ident_ctx.scope_check({GLOBAL, FUNCTION}));
        CHECK(false == ident_ctx.scope_check({GLOBAL}));
    }
    SECTION("scope max nesting")
    {
        JSIdentifierCtx ident_ctx_limited(DEPTH, 2, s_ignored_ids, s_ignored_props);

        CHECK(true == ident_ctx_limited.scope_push(JSProgramScopeType::FUNCTION));
        CHECK(true == ident_ctx_limited.scope_check({GLOBAL, FUNCTION}));

        CHECK(false == ident_ctx_limited.scope_push(JSProgramScopeType::FUNCTION));
        CHECK(true == ident_ctx_limited.scope_check({GLOBAL, FUNCTION}));
        CHECK(false == ident_ctx_limited.scope_push(JSProgramScopeType::FUNCTION));
        CHECK(true == ident_ctx_limited.scope_check({GLOBAL, FUNCTION}));

        CHECK(true == ident_ctx_limited.scope_pop(JSProgramScopeType::FUNCTION));
        CHECK(true == ident_ctx_limited.scope_push(JSProgramScopeType::FUNCTION));
        CHECK(true == ident_ctx_limited.scope_check({GLOBAL, FUNCTION}));
    }
}
