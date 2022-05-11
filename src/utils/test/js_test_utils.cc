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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "utils/test/js_test_utils.h"

#include "catch/catch.hpp"

namespace snort
{
[[noreturn]] void FatalError(const char*, ...)
{ exit(EXIT_FAILURE); }
void trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) { }
uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(const Packet&) { }
}

THREAD_LOCAL const snort::Trace* http_trace = nullptr;

using namespace snort;

void JSTokenizerTester::test_function_scopes(const std::list<ScopeCase>& pdus)
{
    for (auto pdu : pdus)
    {
        const char* source;
        const char* expected;
        std::list<FuncType> exp_stack;
        std::tie(source, expected, exp_stack) = pdu;

        normalizer.normalize(source, strlen(source));
        std::string result_buf(normalizer.get_script(), normalizer.script_size());
        CHECK(result_buf == expected);

        auto tmp_stack(normalizer.get_tokenizer().scope_stack);
        CHECK(tmp_stack.size() == exp_stack.size());
        for (auto func_it = exp_stack.rbegin(); func_it != exp_stack.rend() and !tmp_stack.empty();
            func_it++)
        {
            CHECK(tmp_stack.top().func_call_type == *func_it);
            tmp_stack.pop();
        }
    }
}

bool JSTokenizerTester::is_unescape_nesting_seen() const
{
    return normalizer.is_unescape_nesting_seen();
}

void test_scope(const char* context, const std::list<JSProgramScopeType>& stack)
{
    std::string buf(context);
    buf += "</script>";
    JSIdentifierCtx ident_ctx(norm_depth, max_scope_depth, s_ignored_ids, s_ignored_props);
    JSNormalizer normalizer(ident_ctx, norm_depth, max_template_nesting, max_bracket_depth);
    normalizer.normalize(buf.c_str(), buf.size());
    CHECK(ident_ctx.get_types() == stack);
}

void test_normalization(const char* source, const char* expected)
{
    JSIdentifierCtx ident_ctx(norm_depth, max_scope_depth, s_ignored_ids, s_ignored_props);
    JSNormalizer normalizer(ident_ctx, norm_depth, max_template_nesting, max_bracket_depth);
    normalizer.normalize(source, strlen(source));
    std::string result_buf(normalizer.get_script(), normalizer.script_size());
    CHECK(result_buf == expected);
}

void test_normalization_bad(const char* source, const char* expected, JSTokenizer::JSRet eret)
{
    JSIdentifierCtx ident_ctx(norm_depth, max_scope_depth, s_ignored_ids, s_ignored_props);
    JSNormalizer normalizer(ident_ctx, norm_depth, max_template_nesting, max_bracket_depth);
    auto ret = normalizer.normalize(source, strlen(source));
    std::string result_buf(normalizer.get_script(), normalizer.script_size());
    CHECK(eret == ret);
    CHECK(result_buf == expected);
}

void test_normalization_mixed_encoding(const char* source, const char* expected)
{
    JSIdentifierCtx ident_ctx(norm_depth, max_scope_depth, s_ignored_ids, s_ignored_props);
    JSNormalizer normalizer(ident_ctx, norm_depth, max_template_nesting, max_bracket_depth);
    auto ret = normalizer.normalize(source, strlen(source));
    std::string result_buf(normalizer.get_script(), normalizer.script_size());
    CHECK(ret == JSTokenizer::JSRet::SCRIPT_CONTINUE);
    CHECK(normalizer.is_mixed_encoding_seen());
    CHECK(result_buf == expected);
}

void test_normalization(const std::vector<PduCase>& pdus)
{
    JSIdentifierCtx ident_ctx(norm_depth, max_scope_depth, s_ignored_ids, s_ignored_props);
    JSNormalizer normalizer(ident_ctx, norm_depth, max_template_nesting, max_bracket_depth);

    for (const auto& pdu : pdus)
    {
        const char* source = pdu.first;
        const char* expected = pdu.second;
        normalizer.normalize(source, strlen(source));
        std::string result_buf(normalizer.get_script(), normalizer.script_size());
        CHECK(result_buf == expected);
    }
}

void test_normalization(const std::list<ScopedPduCase>& pdus)
{
    JSIdentifierCtx ident_ctx(norm_depth, max_scope_depth, s_ignored_ids, s_ignored_props);
    JSNormalizer normalizer(ident_ctx, norm_depth, max_template_nesting, max_bracket_depth);
    for (auto pdu:pdus)
    {
        const char* source;
        const char* expected;
        std::list<JSProgramScopeType> stack;
        std::tie(source,expected,stack) = pdu;
        normalizer.normalize(source, strlen(source));
        std::string result_buf(normalizer.get_script(), normalizer.script_size());
        CHECK(ident_ctx.get_types() == stack);
        CHECK(result_buf == expected);
    }
}
