//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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
// js_norm_benchmark.cc authors Danylo Kyrylov <dkyrylov@cisco.com>, Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef BENCHMARK_TEST

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>
#include <string>

#include "catch/catch.hpp"

#include "js_norm/js_identifier_ctx.h"
#include "js_norm/js_normalizer.h"

#include "js_test_utils.h"

using namespace jsn;

static constexpr const char* s_closing_tag = "</script>";

const int max_depth = default_config.norm_depth;

static const std::string make_input(const char* begin, const char* mid, const char* end, size_t len)
{
    std::string str(begin);
    int fill = (len - strlen(begin) - strlen(end) - strlen(s_closing_tag)) / strlen(mid);
    for (int i = 0; i < fill; ++i)
        str.append(mid);
    str.append(end);
    str.append(s_closing_tag);
    return str;
}

static const std::string make_input_repeat(const char* pattern, size_t depth)
{
    std::string str;
    size_t fill = (depth - strlen(s_closing_tag))/strlen(pattern);
    for (size_t it = 0; it < fill; ++it)
        str.append(pattern);

    str.append(s_closing_tag);
    return str;
}

static JSTokenizer::JSRet norm_ret(JSNormalizer& normalizer, const std::string& input)
{
    normalizer.rewind_output();
    return normalizer.normalize(input.c_str(), input.size());
}

TEST_CASE("JS Normalizer, literals by 8 K", "[JSNormalizer]")
{
    auto conf = default_config.derive({norm_depth(unlim_depth), normalize_identifiers(false)});
    JSTokenizerTester tester(conf);
    JSNormalizer& normalizer = tester.normalizer;
    char dst[max_depth];

    constexpr size_t size = 1 << 13;

    auto data_pl = make_input("", ".", "", size);
    auto data_ws = make_input("", " ", "", size);
    auto data_bc = make_input("/*", " ", "*/", size);
    auto data_dq = make_input("\"", " ", "\"", size);

    BENCHMARK("memcpy()")
    {
        return memcpy(dst, data_pl.c_str(), data_pl.size());
    };

    REQUIRE(norm_ret(normalizer, data_ws) == JSTokenizer::SCRIPT_ENDED);
    BENCHMARK("whitespaces")
    {
        normalizer.rewind_output();
        return normalizer.normalize(data_ws.c_str(), data_ws.size());
    };

    REQUIRE(norm_ret(normalizer, data_bc) == JSTokenizer::SCRIPT_ENDED);
    BENCHMARK("block comment")
    {
        normalizer.rewind_output();
        return normalizer.normalize(data_bc.c_str(), data_bc.size());
    };

    REQUIRE(norm_ret(normalizer, data_dq) == JSTokenizer::SCRIPT_ENDED);
    BENCHMARK("double quotes string")
    {
        normalizer.rewind_output();
        return normalizer.normalize(data_dq.c_str(), data_dq.size());
    };
}

TEST_CASE("JS Normalizer, literals by 64 K", "[JSNormalizer]")
{
    auto conf = default_config.derive({norm_depth(unlim_depth), normalize_identifiers(false)});
    JSTokenizerTester tester(conf);
    JSNormalizer& normalizer = tester.normalizer;
    char dst[max_depth];

    constexpr size_t size = 1 << 16;

    auto data_pl = make_input("", ".", "", size);
    auto data_ws = make_input("", " ", "", size);
    auto data_bc = make_input("/*", " ", "*/", size);
    auto data_dq = make_input("\"", " ", "\"", size);

    BENCHMARK("memcpy()")
    {
        return memcpy(dst, data_pl.c_str(), data_pl.size());
    };

    REQUIRE(norm_ret(normalizer, data_ws) == JSTokenizer::SCRIPT_ENDED);
    BENCHMARK("whitespaces")
    {
        normalizer.rewind_output();
        return normalizer.normalize(data_ws.c_str(), data_ws.size());
    };

    REQUIRE(norm_ret(normalizer, data_bc) == JSTokenizer::SCRIPT_ENDED);
    BENCHMARK("block comment")
    {
        normalizer.rewind_output();
        return normalizer.normalize(data_bc.c_str(), data_bc.size());
    };

    REQUIRE(norm_ret(normalizer, data_dq) == JSTokenizer::SCRIPT_ENDED);
    BENCHMARK("double quotes string")
    {
        normalizer.rewind_output();
        return normalizer.normalize(data_dq.c_str(), data_dq.size());
    };
}

TEST_CASE("JS Normalizer, id normalization", "[JSNormalizer]")
{
    // around 11 000 identifiers
    std::string input;
    for (int it = 0; it < max_depth; ++it)
        input.append("n" + std::to_string(it) + " ");

    input.resize(max_depth - strlen(s_closing_tag));
    input.append(s_closing_tag, strlen(s_closing_tag));

    auto bench_config = default_config.derive({norm_depth(unlim_depth)});

    {
        auto conf = bench_config.derive({normalize_identifiers(false)});
        JSTokenizerTester tester(conf);
        JSNormalizer& normalizer_wo_ident = tester.normalizer;

        REQUIRE(norm_ret(normalizer_wo_ident, input) == JSTokenizer::SCRIPT_ENDED);
        BENCHMARK("without substitution")
        {
            normalizer_wo_ident.rewind_output();
            return normalizer_wo_ident.normalize(input.c_str(), input.size());
        };
    }

    {
        auto conf = bench_config.derive({ignored_ids_list({}), ignored_properties_list({})});
        JSTokenizerTester tester(conf);
        JSNormalizer& normalizer_w_ident = tester.normalizer;

        REQUIRE(norm_ret(normalizer_w_ident, input) == JSTokenizer::SCRIPT_ENDED);
        BENCHMARK("with substitution")
        {
            normalizer_w_ident.rewind_output();
            return normalizer_w_ident.normalize(input.c_str(), input.size());
        };
    }

    {
        auto conf = bench_config.derive({ignored_ids_list({"n"}), ignored_properties_list({"n"})});
        JSTokenizerTester tester(conf);
        JSNormalizer& normalizer_iids = tester.normalizer;

        REQUIRE(norm_ret(normalizer_iids, input) == JSTokenizer::SCRIPT_ENDED);
        BENCHMARK("with ignored identifiers")
        {
            normalizer_iids.rewind_output();
            return normalizer_iids.normalize(input.c_str(), input.size());
        };
    }
}

TEST_CASE("JS Normalizer, scope tracking", "[JSNormalizer]")
{
    constexpr uint32_t depth = 65535;
    auto conf = default_config.derive({norm_depth(unlim_depth),normalize_identifiers(false),max_bracket_depth(depth)});
    JSTokenizerTester tester(conf);
    JSNormalizer& normalizer = tester.normalizer;

    auto src_ws = make_input("", " ", "", depth);
    auto src_brace_rep = make_input_repeat("{}", depth);
    auto src_paren_rep = make_input_repeat("()", depth);
    auto src_bracket_rep = make_input_repeat("[]", depth);

    REQUIRE(norm_ret(normalizer, src_ws) == JSTokenizer::SCRIPT_ENDED);
    BENCHMARK("whitespaces")
    {
        normalizer.rewind_output();
        return normalizer.normalize(src_ws.c_str(), src_ws.size());
    };

    REQUIRE(norm_ret(normalizer, src_brace_rep) == JSTokenizer::SCRIPT_ENDED);
    BENCHMARK("...{}{}{}...")
    {
        normalizer.rewind_output();
        return normalizer.normalize(src_brace_rep.c_str(), src_brace_rep.size());
    };

    REQUIRE(norm_ret(normalizer, src_paren_rep) == JSTokenizer::SCRIPT_ENDED);
    BENCHMARK("...()()()...")
    {
        normalizer.rewind_output();
        return normalizer.normalize(src_paren_rep.c_str(), src_paren_rep.size());
    };

    REQUIRE(norm_ret(normalizer, src_bracket_rep) == JSTokenizer::SCRIPT_ENDED);
    BENCHMARK("...[][][]...")
    {
        normalizer.rewind_output();
        return normalizer.normalize(src_bracket_rep.c_str(), src_bracket_rep.size());
    };
}

TEST_CASE("JS Normalizer, automatic semicolon", "[JSNormalizer]")
{
    auto w_semicolons = make_input("", "a;\n", "", max_depth);
    auto wo_semicolons = make_input("", "a \n", "", max_depth);
    const char* src_w_semicolons = w_semicolons.c_str();
    const char* src_wo_semicolons = wo_semicolons.c_str();
    size_t src_len = w_semicolons.size();

    auto conf = default_config.derive({norm_depth(unlim_depth),normalize_identifiers(false)});
    JSTokenizerTester tester(conf);
    JSNormalizer& normalizer_wo_ident = tester.normalizer;

    REQUIRE(norm_ret(normalizer_wo_ident, w_semicolons) == JSTokenizer::SCRIPT_ENDED);
    BENCHMARK("without semicolon insertion")
    {
        normalizer_wo_ident.rewind_output();
        return normalizer_wo_ident.normalize(src_w_semicolons, src_len);
    };

    REQUIRE(norm_ret(normalizer_wo_ident, wo_semicolons) == JSTokenizer::SCRIPT_ENDED);
    BENCHMARK("with semicolon insertion")
    {
        normalizer_wo_ident.rewind_output();
        return normalizer_wo_ident.normalize(src_wo_semicolons, src_len);
    };
}

TEST_CASE("JS Normalizer, unescape", "[JSNormalizer]")
{
    auto str_unescape = make_input("'", "\\u0061", "'", max_depth);
    auto f_unescape = make_input_repeat("unescape('')", max_depth);
    const char* src_str_unescape = str_unescape.c_str();
    const char* src_f_unescape = f_unescape.c_str();
    size_t src_len = max_depth;

    auto conf = default_config.derive({norm_depth(unlim_depth)});
    JSTokenizerTester tester(conf);
    JSNormalizer& norm = tester.normalizer;

    REQUIRE(norm_ret(norm, str_unescape) == JSTokenizer::SCRIPT_ENDED);
    BENCHMARK("unescape sequence")
    {
        norm.rewind_output();
        return norm.normalize(src_str_unescape, src_len);
    };

    REQUIRE(norm_ret(norm, f_unescape) == JSTokenizer::SCRIPT_ENDED);
    BENCHMARK("unescape function tracking")
    {
        norm.rewind_output();
        return norm.normalize(src_f_unescape, src_len);
    };
}

#endif

