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
// js_test_utils.cc author Danylo Kyrylov <dkyrylov@cisco.com>

#ifndef JS_TEST_UTILS_H
#define JS_TEST_UTILS_H

#include <list>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

#include "utils/js_identifier_ctx.h"
#include "utils/js_normalizer.h"

constexpr int unlim_depth = -1;
constexpr int norm_depth = 65535;
constexpr int max_template_nesting = 4;
constexpr int max_bracket_depth = 256;
constexpr int max_scope_depth = 256;
static const std::unordered_set<std::string> s_ignored_ids {
    "console", "eval", "document", "unescape", "decodeURI", "decodeURIComponent", "String",
    "name", "u"
};

static const std::unordered_set<std::string> s_ignored_props {
    "watch", "unwatch", "split", "reverse", "join", "name", "w"
};

namespace snort
{
[[noreturn]] void FatalError(const char*, ...);
void trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list);
}

class JSIdentifierCtxStub : public JSIdentifierCtxBase
{
public:
    JSIdentifierCtxStub() = default;

    const char* substitute(const char* identifier, bool) override
    { return identifier; }
    virtual void add_alias(const char*, const std::string&&) override {}
    virtual const char* alias_lookup(const char* alias) const override
    { return alias; }
    bool is_ignored(const char*) const override
    { return false; }
    bool scope_push(JSProgramScopeType) override { return true; }
    bool scope_pop(JSProgramScopeType) override { return true; }
    void reset() override {}
    size_t size() const override { return 0; }
};

class JSTokenizerTester
{
public:
    JSTokenizerTester(int32_t depth, uint32_t max_scope_depth,
        const std::unordered_set<std::string>& ignored_ids,
        const std::unordered_set<std::string>& ignored_props,
        uint8_t max_template_nesting, uint32_t max_bracket_depth)
        :
        ident_ctx(depth, max_scope_depth, ignored_ids, ignored_props),
        normalizer(ident_ctx, depth, max_template_nesting, max_bracket_depth)
    { }

    typedef JSTokenizer::FuncType FuncType;
    typedef std::tuple<const char*, const char*, std::list<FuncType>> ScopeCase;
    void test_function_scopes(const std::list<ScopeCase>& pdus);
    bool is_unescape_nesting_seen() const;

private:
    JSIdentifierCtx ident_ctx;
    snort::JSNormalizer normalizer;
};

void test_scope(const char* context, const std::list<JSProgramScopeType>& stack);
void test_normalization(const char* source, const char* expected);
void test_normalization_bad(const char* source, const char* expected, JSTokenizer::JSRet eret);
void test_normalization_mixed_encoding(const char* source, const char* expected);
typedef std::pair<const char*, const char*> PduCase;
// source, expected for a single PDU
void test_normalization(const std::vector<PduCase>& pdus);
typedef std::tuple<const char*,const char*, std::list<JSProgramScopeType>> ScopedPduCase;
// source, expected, and current scope type stack for a single PDU
void test_normalization(const std::list<ScopedPduCase>& pdus);

#endif // JS_TEST_UTILS_H
