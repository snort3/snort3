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
// js_identifier_ctx.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "js_identifier_ctx.h"

#include <cassert>

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

#define MAX_LAST_NAME     65535
#define HEX_DIGIT_MASK       15

static const char hex_digits[] = 
{
    '0', '1','2','3', '4', '5', '6', '7', '8','9', 'a', 'b', 'c', 'd', 'e', 'f'
};

static inline std::string format_name(int32_t num)
{
    std::string name("var_");
    name.reserve(8);
    name.push_back(hex_digits[(num >> 12) & HEX_DIGIT_MASK]); 
    name.push_back(hex_digits[(num >> 8) & HEX_DIGIT_MASK]); 
    name.push_back(hex_digits[(num >> 4) & HEX_DIGIT_MASK]);
    name.push_back(hex_digits[num & HEX_DIGIT_MASK]); 

    return name;
}

JSIdentifierCtx::JSIdentifierCtx(int32_t depth, uint32_t max_scope_depth,
    const std::unordered_set<std::string>& ident_built_in)
    : ident_built_in(ident_built_in), depth(depth), max_scope_depth(max_scope_depth)
{
    scopes.emplace_back(JSProgramScopeType::GLOBAL);
}

const char* JSIdentifierCtx::substitute(const char* identifier)
{
    const auto it = ident_names.find(identifier);
    if (it != ident_names.end())
        return it->second.c_str();

    if (ident_last_name >= depth || ident_last_name > MAX_LAST_NAME)
        return nullptr;

    ident_names[identifier] = format_name(ident_last_name++);
    HttpModule::increment_peg_counts(HttpEnums::PEG_JS_IDENTIFIER);
    return ident_names[identifier].c_str();
}

bool JSIdentifierCtx::built_in(const char* identifier) const
{
    return ident_built_in.count(identifier);
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
    ident_last_name = 0;

    ident_names.clear();
    scopes.clear();
    scopes.emplace_back(JSProgramScopeType::GLOBAL);
}

void JSIdentifierCtx::ProgramScope::add_alias(const char* alias, const std::string& value)
{
    assert(alias);
    aliases[alias] = value;
}

const char* JSIdentifierCtx::ProgramScope::get_alias_value(const char* alias) const
{
    assert(alias);

    const auto it = aliases.find(alias);
    if (it != aliases.end())
        return it->second.c_str();
    else
        return nullptr;
}

// advanced program scope access for testing

#ifdef CATCH_TEST_BUILD

void JSIdentifierCtx::add_alias(const char* alias, const std::string& value)
{
    assert(alias);
    assert(!scopes.empty());
    scopes.back().add_alias(alias, value);
}

const char* JSIdentifierCtx::alias_lookup(const char* alias) const
{
    assert(alias);

    for (auto it = scopes.rbegin(); it != scopes.rend(); ++it)
    {
        if (const char* value = it->get_alias_value(alias))
            return value;
    }
    return nullptr;
}

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

bool JSIdentifierCtx::scope_contains(size_t pos, const char* alias) const
{
    size_t offset = 0;
    for (auto it = scopes.begin(); it != scopes.end(); ++it, ++offset)
    {
        if (offset == pos)
            return it->get_alias_value(alias);
    }
    assert(false);
    return false;
}

#endif // CATCH_TEST_BUILD

