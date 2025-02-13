//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "js_test_utils.h"

#include "catch/catch.hpp"

using namespace jsn;

JSTokenizerTester::JSTokenizerTester(const JSTestConfig& conf) :
    ident_ctx(conf.identifier_depth,
        conf.max_scope_depth,
        conf.ignored_ids_list,
        conf.ignored_properties_list),
    normalizer(
        conf.normalize_identifiers ?
            static_cast<JSIdentifier&>(ident_ctx) :
            static_cast<JSIdentifier&>(ident_ctx_stub),
        conf.norm_depth,
        conf.max_template_nesting,
        conf.max_bracket_depth,
        conf.max_token_buf_size
    ),
    config(conf)
{ }

void JSTokenizerTester::do_pdu(const std::string& source)
{
    last_source = source;
    last_return = normalizer.normalize(last_source.c_str(), last_source.size(),
        config.normalize_as_external.is_set() and config.normalize_as_external);
}

void JSTokenizerTester::check_output(const std::string& expected)
{
    std::string result_str;

    if (config.use_expected_for_last_pdu.is_set() and config.use_expected_for_last_pdu)
    {
        auto size = normalizer.script_size();
        auto temp_buf = normalizer.take_script();
        result_str = {temp_buf, size};
        delete[] temp_buf;
    }
    else
        result_str = {normalizer.get_script(), normalizer.script_size()};

    CHECK(result_str == expected);
}

void JSTokenizerTester::run_checks(const JSTestConfig& checks)
{
    if (checks.return_code.is_set())
        CHECK(last_return == checks.return_code);

    if (checks.check_open_tag.is_set())
        CHECK((normalizer.is_opening_tag_seen() == checks.check_open_tag));

    if (checks.check_closing_tag.is_set())
        CHECK((normalizer.is_closing_tag_seen() == checks.check_closing_tag));

    if (checks.check_mixed_encoding.is_set())
        CHECK((normalizer.is_mixed_encoding_seen() == checks.check_mixed_encoding));

    if (checks.check_unescape_nesting.is_set())
        CHECK((normalizer.is_unescape_nesting_seen() == checks.check_unescape_nesting));

    if (checks.expected_cursor_pos.is_set())
        CHECK((normalizer.get_src_next() - last_source.c_str()) == checks.expected_cursor_pos);

    if (checks.temporary_buffer.is_set())
        CHECK(std::string(normalizer.get_tmp_buf(),
            normalizer.get_tmp_buf_size()) == static_cast<std::string>(checks.temporary_buffer));
}

void JSTestConfig::test_function_scopes(const std::list<FunctionScopeCase>& pdus)
{
    JSTokenizerTester tester(*this);

    for (auto pdu : pdus)
    {
        std::string source;
        std::string expected;
        std::list<FuncType> exp_stack;
        std::tie(source, expected, exp_stack) = pdu;

        tester.do_pdu(source);
        tester.check_output(expected);

        auto tmp_stack(tester.normalizer.get_tokenizer().scope_stack);
        CHECK(tmp_stack.size() == exp_stack.size());
        for (auto func_it = exp_stack.rbegin(); func_it != exp_stack.rend() and !tmp_stack.empty();
            func_it++)
        {
            CHECK(tmp_stack.top().func_call_type == *func_it);
            tmp_stack.pop();
        }
    }
}

void JSTestConfig::test_function_scopes(const std::list<FunctionScopeCase>& pdus, const Overrides& overrides)
{
    derive(overrides).test_function_scopes(pdus);
}

JSTestConfig::JSTestConfig(const Overrides& values)
{
    set_overrides(values);
}

JSTestConfig JSTestConfig::derive(const Overrides& values) const
{
    JSTestConfig new_config(*this);
    new_config.set_overrides(values);
    return new_config;
}

void JSTestConfig::test_scope(const std::string& context, const std::list<JSProgramScopeType>& stack) const
{
    JSTokenizerTester tester(*this);
    std::string buf = context + "</script>";

    tester.do_pdu(buf);
    CHECK(tester.ident_ctx.get_types() == stack);
}

void JSTestConfig::test_scope(const std::string& context, const std::list<JSProgramScopeType>& stack,
    const Overrides& overrides) const
{
    derive(overrides).test_scope(context, stack);
}

void JSTestConfig::test_normalization(const std::string& source, const std::string& expected) const
{
    JSTokenizerTester tester(*this);

    tester.do_pdu(source);

    tester.check_output(expected);
    tester.run_checks(*this);
}

void JSTestConfig::test_normalization(const std::string& source, const std::string& expected,
    const Overrides& overrides) const
{
    derive(overrides).test_normalization(source, expected);
}

void JSTestConfig::test_normalization(const std::vector<PduCase>& pdus) const
{
    JSTokenizerTester tester(*this);

    for (const auto& pdu : pdus)
    {
        auto source = pdu.first;
        auto expected = pdu.second;
        tester.do_pdu(source);
        tester.check_output(expected);
    }

    tester.run_checks(*this);
}

void JSTestConfig::test_normalization(const std::vector<PduCase>& pdus, const Overrides& overrides) const
{
    derive(overrides).test_normalization(pdus);
}

void JSTestConfig::test_normalization(const std::list<ScopedPduCase>& pdus) const
{
    JSTokenizerTester tester(*this);

    for (auto pdu:pdus)
    {
        std::string source;
        std::string expected;
        std::list<JSProgramScopeType> stack;
        std::tie(source, expected, stack) = pdu;
        tester.do_pdu(source);
        tester.check_output(expected);
        CHECK(tester.ident_ctx.get_types() == stack);
    }

    tester.run_checks(*this);
}

void JSTestConfig::test_normalization(const std::list<ScopedPduCase>& pdus, const Overrides& overrides) const
{
    derive(overrides).test_normalization(pdus);
}

void JSTestConfig::test_normalization_combined(const std::list<std::string>& pdu_sources,
    const std::string& combined_expected) const
{
    JSTokenizerTester tester(*this);

    for (const auto& source : pdu_sources)
        tester.do_pdu(source);

    tester.check_output(combined_expected);
    tester.run_checks(*this);
}

void JSTestConfig::test_normalization_combined(const std::list<std::string>& pdu_sources,
    const std::string& combined_expected, const Overrides& overrides) const
{
    derive(overrides).test_normalization_combined(pdu_sources, combined_expected);
}

void test_scope(const std::string& context, const std::list<JSProgramScopeType>& stack)
{
    default_config.test_scope(context, stack);
}
void test_normalization(const std::string& source, const std::string& expected, const Overrides& overrides)
{
    default_config.test_normalization(source, expected, overrides);
}

void test_normalization_noident(const std::string& source, const std::string& expected, const Overrides& overrides)
{
    default_config.derive(overrides).test_normalization(source, expected, {normalize_identifiers(false)});
}

void test_normalization_bad(const std::string& source, const std::string& expected, JSTokenizer::JSRet eret)
{
    default_config.test_normalization(source, expected, {return_code(eret)});
}

void test_normalization_mixed_encoding(const std::string& source, const std::string& expected)
{
    default_config.test_normalization(source, expected, {check_mixed_encoding(true)});
}

void test_normalization(const std::vector<PduCase>& pdus, const Overrides& overrides)
{
    default_config.test_normalization(pdus, overrides);
}

void test_normalization(const std::list<ScopedPduCase>& pdus, const Overrides& overrides)
{
    default_config.test_normalization(pdus, overrides);
}

void test_normalization_combined(const std::list<std::string>& pdu_sources, const std::string& total_expected,
    const Overrides& overrides)
{
    default_config.test_normalization_combined(pdu_sources, total_expected, overrides);
}

