//--------------------------------------------------------------------------
// Copyright (C) 2022-2025 Cisco and/or its affiliates. All rights reserved.
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
// pdf_tokenizer_benchmark.cc author Cisco

#ifdef BENCHMARK_TEST

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>
#include <string>

#include <FlexLexer.h>

#include "catch/catch.hpp"
#include "helpers/streambuf.h"
#include "js_norm/pdf_tokenizer.h"

using namespace jsn;
using namespace snort;
using namespace std;

static constexpr int nesting_level = 10;

static const string make_input(const char* begin, const char* mid, const char* end, size_t len)
{
    string str(begin);
    int fill = (len - strlen(begin) - strlen(end)) / strlen(mid);

    for (int i = 0; i < fill; ++i)
        str.append(mid);
    str.append(end);

    return str;
}

static const string make_input_repeat(const char* pattern, int cnt)
{
    string str;

    while (cnt--)
        str.append(pattern);

    return str;
}

#define set_input(input)                                                \
    buf_in.pubsetbuf(nullptr, 0)->pubsetbuf((char*)(input).c_str(), (input).size()); \
    buf_out.reserve((input).size())                                     \

#define rewind()                                                \
    buf_in.pubseekoff(0, ios_base::beg, ios_base::in);          \
    buf_out.pubseekoff(0, ios_base::beg, ios_base::out)         \

TEST_CASE("PDF Tokenizer, literals by 8 K", "[PDFTokenizer]")
{
    constexpr size_t size = 1 << 13;

    const auto data_cpy = make_input("",           " ", "",            size);
    const auto data_wsp = make_input("1 1 obj\n",  " ", "   \nendobj\n", size);
    const auto data_com = make_input("1 2 obj\n%", "c", "\n \nendobj\n", size);
    const auto data_str = make_input("1 3 obj\n(", "s", ")  \nendobj\n", size);
    const auto data_hex = make_input("1 4 obj\n<", "0", ">  \nendobj\n", size);
    const auto data_stm = make_input("1 5 obj\n<</Length 8192>>stream\n", ".",
        "\nendstream\nendobj\n", size);

    char dst[size + 128];
    istreambuf_glue buf_in;
    ostreambuf_infl buf_out;
    istream in(&buf_in);
    ostream out(&buf_out);
    char* buf = nullptr;
    int len;
    PDFTokenizer parser(in, out, buf, len, nesting_level);

    BENCHMARK("memcpy()")
    {
        return memcpy(dst, data_cpy.c_str(), data_cpy.size());
    };

    set_input(data_wsp);
    BENCHMARK("whitespace")
    {
        rewind();
        return parser.process();
    };

    set_input(data_com);
    BENCHMARK("comment")
    {
        rewind();
        return parser.process();
    };

    set_input(data_str);
    BENCHMARK("literal string")
    {
        rewind();
        return parser.process();
    };

    set_input(data_hex);
    BENCHMARK("hexadecimal string")
    {
        rewind();
        return parser.process();
    };

    set_input(data_stm);
    BENCHMARK("stream")
    {
        rewind();
        return parser.process();
    };

    delete[] buf;
}

TEST_CASE("PDF Parser, literals by 64 K", "[PDFTokenizer]")
{
    constexpr size_t size = 1 << 16;

    const auto data_cpy = make_input("",           " ", "",            size);
    const auto data_wsp = make_input("1 1 obj\n",  " ", "   \nendobj\n", size);
    const auto data_com = make_input("1 2 obj\n%", "c", "\n \nendobj\n", size);
    const auto data_str = make_input("1 3 obj\n(", "s", ")  \nendobj\n", size);
    const auto data_hex = make_input("1 4 obj\n<", "0", ">  \nendobj\n", size);
    const auto data_stm = make_input("1 5 obj\n<</Length 65536>>stream\n", ".",
        "\nendstream\nendobj\n", size);

    char dst[size + 128];
    istreambuf_glue buf_in;
    ostreambuf_infl buf_out;
    istream in(&buf_in);
    ostream out(&buf_out);
    char* buf = nullptr;
    int len;
    PDFTokenizer parser(in, out, buf, len, nesting_level);

    BENCHMARK("memcpy()")
    {
        return memcpy(dst, data_cpy.c_str(), data_cpy.size());
    };

    set_input(data_wsp);
    BENCHMARK("whitespace")
    {
        rewind();
        return parser.process();
    };

    set_input(data_com);
    BENCHMARK("comment")
    {
        rewind();
        return parser.process();
    };

    set_input(data_str);
    BENCHMARK("literal string")
    {
        rewind();
        return parser.process();
    };

    set_input(data_hex);
    BENCHMARK("hexadecimal string")
    {
        rewind();
        return parser.process();
    };

    set_input(data_stm);
    BENCHMARK("stream")
    {
        rewind();
        return parser.process();
    };

    delete[] buf;
}

TEST_CASE("PDF Tokenizer, indirect objects", "[PDFTokenizer]")
{
    // 30 * 2048 = 61440
    const auto data = make_input_repeat("1 0 obj\n % any object\n endobj\n", 2048);

    istreambuf_glue buf_in;
    ostreambuf_infl buf_out;
    istream in(&buf_in);
    ostream out(&buf_out);
    char* buf = nullptr;
    int len;
    PDFTokenizer parser(in, out, buf, len, nesting_level);

    set_input(data);
    BENCHMARK("same object repeated")
    {
        rewind();
        return parser.process();
    };

    delete[] buf;
}

#endif
