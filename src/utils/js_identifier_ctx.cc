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

#define TYPE_NORMALIZED     1
#define TYPE_IGNORED_ID     2
#define TYPE_IGNORED_PROP   4

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
    const std::unordered_set<std::string>& ignored_ids_list,
    const std::unordered_set<std::string>& ignored_props_list)
    : ignored_ids_list(ignored_ids_list), ignored_props_list(ignored_props_list), 
    max_scope_depth(max_scope_depth)
{
    init_norm_names();

    norm_name = norm_names;
    norm_name_end = norm_names + NORM_NAME_SIZE * std::min(depth, NORM_NAME_CNT);
    scopes.emplace_back(JSProgramScopeType::GLOBAL);

    init_ignored_names();
}

const char* JSIdentifierCtx::substitute(unsigned char c, bool is_property)
{
    auto p = id_fast[c];
    if (is_substituted(p, is_property))
        return is_property ? p.prop_name : p.id_name;

    return acquire_norm_name(id_fast[c]);
}

const char* JSIdentifierCtx::substitute(const char* id_name, bool is_property)
{
    assert(*id_name);

    if (id_name[1] == '\0')
        return substitute(*id_name, is_property);

    const auto it = id_names.find(id_name);
    if (it != id_names.end() && is_substituted(it->second, is_property))
        return is_property ? it->second.prop_name : it->second.id_name;

    return acquire_norm_name(id_names[id_name]);
}

bool JSIdentifierCtx::is_ignored(const char* id_name) const
{
    return id_name < norm_names ||
        id_name >= norm_names + NORM_NAME_SIZE * NORM_NAME_CNT;
}

bool JSIdentifierCtx::is_substituted(const NormId& id, bool is_property)
{
    return ((id.type & TYPE_NORMALIZED) != 0) ||
        (!is_property && ((id.type & TYPE_IGNORED_ID) != 0)) ||
        (is_property && ((id.type & TYPE_IGNORED_PROP) != 0));
}

const char* JSIdentifierCtx::acquire_norm_name(NormId& id)
{
    if (norm_name >= norm_name_end)
        return nullptr;

    auto n = norm_name;
    norm_name += NORM_NAME_SIZE;
    HttpModule::increment_peg_counts(HttpEnums::PEG_JS_IDENTIFIER);

    if (id.prop_name || id.id_name)
    {
        id.type |= TYPE_NORMALIZED;
        if ((id.type & TYPE_IGNORED_ID) != 0)
            return id.prop_name = n;
        else if ((id.type & TYPE_IGNORED_PROP) != 0)
            return id.id_name = n;
    }

    return (id = {n, n, TYPE_NORMALIZED}).id_name;
}

void JSIdentifierCtx::init_ignored_names()
{
    for (const auto& iid : ignored_ids_list)
        if (iid.length() == 1)
            id_fast[(unsigned)iid[0]] = {iid.c_str(), nullptr, TYPE_IGNORED_ID};
        else
            id_names[iid] = {iid.c_str(), nullptr, TYPE_IGNORED_ID};

    for (const auto& iprop : ignored_props_list)
    {
        if (iprop.length() == 1)
        {
            id_fast[(unsigned)iprop[0]].prop_name = iprop.c_str();
            id_fast[(unsigned)iprop[0]].type |= TYPE_IGNORED_PROP;
        }
        else
        {
            id_names[iprop].prop_name = iprop.c_str();
            id_names[iprop].type |= TYPE_IGNORED_PROP;
        }
    }
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
    memset(&id_fast, 0, sizeof(id_fast));
    norm_name = norm_names;
    id_names.clear();
    scopes.clear();
    scopes.emplace_back(JSProgramScopeType::GLOBAL);
    init_ignored_names();
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

#if defined(CATCH_TEST_BUILD) || defined(BENCHMARK_TEST)

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

#endif // CATCH_TEST_BUILD || BENCHMARK_TEST
