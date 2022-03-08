//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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
// js_identifier_ctx.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "js_identifier_ctx.h"

#include <cassert>
#include <memory.h>

#if !defined(CATCH_TEST_BUILD) && !defined(BENCHMARK_TEST)
#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http_inspect/http_module.h"
#else
namespace HttpEnums
{
enum PEG_COUNT
{
    PEG_JS_IDENTIFIER
};
}

class HttpModule
{
public:
    static void increment_peg_counts(HttpEnums::PEG_COUNT) {}
};
#endif // CATCH_TEST_BUILD

#define NORM_NAME_SIZE 9 // size of the normalized form plus null symbol
#define NORM_NAME_CNT 65536

static char norm_names[NORM_NAME_SIZE * NORM_NAME_CNT];

static void init_norm_names()
{
    static bool once = false;

    if (once)
        return;

    once = true;

    char* c = norm_names;
    const char hex[] = "0123456789abcdef";

    for (int i = 0; i < NORM_NAME_CNT; ++i)
    {
        *c++ = 'v';
        *c++ = 'a';
        *c++ = 'r';
        *c++ = '_';
        *c++ = hex[(i >> 12) & 0xf];
        *c++ = hex[(i >>  8) & 0xf];
        *c++ = hex[(i >>  4) & 0xf];
        *c++ = hex[(i >>  0) & 0xf];
        *c++ = '\0';
    }

    assert(sizeof(norm_names) == c - norm_names);
}

JSIdentifierCtx::JSIdentifierCtx(int32_t depth, uint32_t max_scope_depth,
    const std::unordered_set<std::string>& ignore_list)
    : ignore_list(ignore_list), max_scope_depth(max_scope_depth)
{
    init_norm_names();

    memset(id_fast, 0, sizeof(id_fast));
    norm_name = norm_names;
    norm_name_end = norm_names + NORM_NAME_SIZE * std::min(depth, NORM_NAME_CNT);
    scopes.emplace_back(JSProgramScopeType::GLOBAL);

    for (const auto& iid : ignore_list)
        if (iid.length() == 1)
            id_fast[(unsigned)iid[0]] = iid.c_str();
        else
            id_names[iid] = iid.c_str();
}

const char* JSIdentifierCtx::substitute(unsigned char c)
{
    auto p = id_fast[c];
    if (p)
        return p;

    if (norm_name >= norm_name_end)
        return nullptr;

    auto n = norm_name;
    norm_name += NORM_NAME_SIZE;
    HttpModule::increment_peg_counts(HttpEnums::PEG_JS_IDENTIFIER);

    return id_fast[c] = n;
}

const char* JSIdentifierCtx::substitute(const char* id_name)
{
    assert(*id_name);

    if (id_name[1] == '\0')
        return substitute(*id_name);

    const auto it = id_names.find(id_name);
    if (it != id_names.end())
        return it->second;

    if (norm_name >= norm_name_end)
        return nullptr;

    auto n = norm_name;
    norm_name += NORM_NAME_SIZE;
    HttpModule::increment_peg_counts(HttpEnums::PEG_JS_IDENTIFIER);

    return id_names[id_name] = n;
}

bool JSIdentifierCtx::is_ignored(const char* id_name) const
{
    return id_name < norm_names ||
        id_name >= norm_names + NORM_NAME_SIZE * NORM_NAME_CNT;
}

bool JSIdentifierCtx::scope_push(JSProgramScopeType t)
{
    assert(t != JSProgramScopeType::GLOBAL && t != JSProgramScopeType::PROG_SCOPE_TYPE_MAX);

    if (scopes.size() >= max_scope_depth)
        return false;

    scopes.emplace_back(t);
    return true;
}

bool JSIdentifierCtx::scope_pop(JSProgramScopeType t)
{
    assert(t != JSProgramScopeType::GLOBAL && t != JSProgramScopeType::PROG_SCOPE_TYPE_MAX);

    if (scopes.back().type() != t)
        return false;

    assert(scopes.size() != 1);
    scopes.pop_back();
    return true;
}

void JSIdentifierCtx::reset()
{
    memset(id_fast, 0, sizeof(id_fast));
    norm_name = norm_names;
    id_names.clear();
    scopes.clear();
    scopes.emplace_back(JSProgramScopeType::GLOBAL);

    for (const auto& iid : ignore_list)
        if (iid.length() == 1)
            id_fast[(unsigned)iid[0]] = iid.c_str();
        else
            id_names[iid] = iid.c_str();
}

void JSIdentifierCtx::add_alias(const char* alias, const std::string&& value)
{
    assert(alias);
    assert(!scopes.empty());

    auto& a = aliases[alias];
    a.emplace_back(std::move(value));

    scopes.back().reference(a);
}

const char* JSIdentifierCtx::alias_lookup(const char* alias) const
{
    assert(alias);

    const auto& i = aliases.find(alias);

    return i != aliases.end() && !i->second.empty()
        ? i->second.back().c_str() : nullptr;
}

// advanced program scope access for testing

#ifdef CATCH_TEST_BUILD

bool JSIdentifierCtx::scope_check(const std::list<JSProgramScopeType>& compare) const
{
    if (scopes.size() != compare.size())
        return false;

    auto cmp = compare.begin();
    for (auto it = scopes.begin(); it != scopes.end(); ++it, ++cmp)
    {
        if (it->type() != *cmp)
            return false;
    }
    return true;
}

const std::list<JSProgramScopeType> JSIdentifierCtx::get_types() const
{
    std::list<JSProgramScopeType> return_list;
    for(const auto& scope:scopes)
    {
        return_list.push_back(scope.type());
    }
    return return_list;
}

#endif // CATCH_TEST_BUILD
