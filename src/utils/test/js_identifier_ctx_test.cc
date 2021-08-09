//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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
#include <vector>

#include "utils/js_identifier_ctx.h"

#define DEPTH 260000

#define FIRST_NAME_SIZE   26
#define LAST_NAME_SIZE  9999

static const char s_ident_first_names[FIRST_NAME_SIZE] =
{
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

TEST_CASE("JSIdentifierCtx::substitute()", "[JSIdentifierCtx]")
{
    SECTION("same name")
    {
        JSIdentifierCtx ident_ctx(DEPTH);

        CHECK(!strcmp(ident_ctx.substitute("a"), "a0"));
        CHECK(!strcmp(ident_ctx.substitute("a"), "a0"));
    }
    SECTION("different names")
    {
        JSIdentifierCtx ident_ctx(DEPTH);

        CHECK(!strcmp(ident_ctx.substitute("a"), "a0"));
        CHECK(!strcmp(ident_ctx.substitute("b"), "a1"));
        CHECK(!strcmp(ident_ctx.substitute("a"), "a0"));
    }
    SECTION("depth reached")
    {
        JSIdentifierCtx ident_ctx(2);

        CHECK(!strcmp(ident_ctx.substitute("a"), "a0"));
        CHECK(!strcmp(ident_ctx.substitute("b"), "a1"));
        CHECK(ident_ctx.substitute("c") == nullptr);
        CHECK(ident_ctx.substitute("d") == nullptr);
        CHECK(!strcmp(ident_ctx.substitute("a"), "a0"));
    }
    SECTION("max names")
    {
        JSIdentifierCtx ident_ctx(DEPTH + 2);

        std::vector<std::string> n, e;
        n.reserve(DEPTH + 2);
        e.reserve(DEPTH);

        for (int it = 0; it < DEPTH + 2; ++it)
            n.push_back("n" + std::to_string(it));

        for (int it_first = 0; it_first < FIRST_NAME_SIZE; ++it_first)
        {
            for (int it_last = 0; it_last <= LAST_NAME_SIZE; ++it_last)
                e.push_back(s_ident_first_names[it_first] + std::to_string(it_last));
        }

        for (int it = 0; it < DEPTH; ++it)
            CHECK(!strcmp(ident_ctx.substitute(n[it].c_str()), e[it].c_str()));

        CHECK(ident_ctx.substitute(n[DEPTH].c_str()) == nullptr);
        CHECK(ident_ctx.substitute(n[DEPTH + 1].c_str()) == nullptr);
    }
}

