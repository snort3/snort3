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
// js_test_utils.cc author Danylo Kyrylov <dkyrylov@cisco.com>

#ifndef JS_TEST_UTILS_H
#define JS_TEST_UTILS_H

#include <list>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

#include "js_norm/js_identifier_ctx.h"
#include "js_norm/js_normalizer.h"

#include "js_test_options.h"

constexpr int unlim_depth = -1;

namespace jsn
{

class JSIdentifierCtxStub : public JSIdentifier
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
};

class JSTestConfig;

class JSTokenizerTester
{
public:
    typedef JSTokenizer::FuncType FuncType;

    JSTokenizerTester(const JSTestConfig& conf);

    void do_pdu(const std::string& source);
    void check_output(const std::string& expected);
    void run_checks(const JSTestConfig& checks);

    JSIdentifierCtx ident_ctx;
    JSIdentifierCtxStub ident_ctx_stub;
    JSNormalizer normalizer;

private:
    const JSTestConfig& config;
    JSTokenizer::JSRet last_return;
    std::string last_source;
};

typedef JSTokenizerTester::FuncType FuncType;

// source, expected for a single PDU
typedef std::pair<std::string, std::string> PduCase;

// source, expected, and current scope type stack for a single PDU
typedef std::tuple<std::string, std::string, std::list<JSProgramScopeType>> ScopedPduCase;
typedef std::tuple<const char*, const char*, std::list<FuncType>> FunctionScopeCase;

class JSTestConfig : public ConfigSet
{
public:
    JSTestConfig(const Overrides& values);
    JSTestConfig derive(const Overrides& values) const;

    JSNormalizer&& make_normalizer() const;

    void test_scope(const std::string& context, const std::list<JSProgramScopeType>& stack) const;
    void test_scope(const std::string& context, const std::list<JSProgramScopeType>& stack,
        const Overrides& overrides) const;

    void test_function_scopes(const std::list<FunctionScopeCase>& pdus);
    void test_function_scopes(const std::list<FunctionScopeCase>& pdus, const Overrides& overrides);

    void test_normalization(const std::string& source, const std::string& expected) const;
    void test_normalization(const std::string& source, const std::string& expected, const Overrides& overrides) const;

    void test_normalization(const std::vector<PduCase>& pdus) const;
    void test_normalization(const std::vector<PduCase>& pdus, const Overrides& overrides) const;

    void test_normalization(const std::list<ScopedPduCase>& pdus) const;
    void test_normalization(const std::list<ScopedPduCase>& pdus, const Overrides& overrides) const;

    void test_normalization_combined(const std::list<std::string>& pdu_sources,
        const std::string& total_expected) const;
    void test_normalization_combined(const std::list<std::string>& pdu_sources,
        const std::string& total_expected, const Overrides& overrides) const;
};

static const JSTestConfig default_config({
    norm_depth(65535),
    identifier_depth(65535),
    max_template_nesting(4),
    max_bracket_depth(256),
    max_scope_depth(256),
    max_token_buf_size(256),
    ignored_ids_list({
        "console", "eval", "document", "unescape", "decodeURI", "decodeURIComponent", "String",
        "name", "u"}),
    ignored_properties_list({
        "watch", "unwatch", "split", "reverse", "join", "name", "w", "catch", "finally"}),
    normalize_identifiers(true)
});

}

void test_scope(const std::string& context, const std::list<jsn::JSProgramScopeType>& stack);
void test_normalization(const std::string& source, const std::string& expected, const Overrides& overrides = {});
void test_normalization_noident(const std::string& source, const std::string& expected,
    const Overrides& overrides = {});
void test_normalization_bad(const std::string& source, const std::string& expected, JSTokenizer::JSRet eret);
void test_normalization_mixed_encoding(const std::string& source, const std::string& expected);
void test_normalization(const std::vector<PduCase>& pdus, const Overrides& overrides = {});
void test_normalization(const std::list<ScopedPduCase>& pdus, const Overrides& overrides = {});
void test_normalization_combined(const std::list<std::string>& pdu_sources, const std::string& total_expected,
    const Overrides& overrides = {});

#endif

