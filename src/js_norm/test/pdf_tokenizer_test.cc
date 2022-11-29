//--------------------------------------------------------------------------
// Copyright (C) 2022-2022 Cisco and/or its affiliates. All rights reserved.
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
// pdf_tokenizer_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <vector>

#include <FlexLexer.h>

#include "catch/catch.hpp"
#include "js_norm/pdf_tokenizer.h"

using namespace jsn;
using namespace std;

typedef pair<string, string> Chunk;

static void test_pdf_proc(const string& source, const string& expected,
    PDFTokenizer::PDFRet ret = PDFTokenizer::PDFRet::EOS)
{
    istringstream in(source);
    ostringstream out;
    PDFTokenizer extractor(in, out);

    auto r = extractor.process();

    CHECK(ret == r);
    CHECK(expected == out.str());
}

static void test_pdf_proc(const vector<Chunk>& chunks)
{
    istringstream in;
    ostringstream out;
    PDFTokenizer extractor(in, out);

    for (auto& chunk : chunks)
    {
        auto src = chunk.first;
        auto exp = chunk.second;

        in.rdbuf()->pubsetbuf((char*)src.c_str(), src.length());
        out.str("");

        auto r = extractor.process();

        CHECK(PDFTokenizer::PDFRet::EOS == r);
        CHECK(exp == out.str());
    }
}

TEST_CASE("basic", "[PDFTokenizer]")
{
    SECTION("no input")
    {
        test_pdf_proc(
            "",
            ""
        );
    }
    SECTION("minimal PDF")
    {
        test_pdf_proc(
            "20 0 obj"
            "<<"
            "/Creator (Acrobat Pro DC 22.1.20169)"
            "/ModDate (D:20220714154535+03'00')"
            "/CreationDate (D:20220714153909+03'00')"
            "/Producer (Acrobat Pro DC 22.1.20169)"
            ">>"
            "endobj",
            ""
        );
    }
    SECTION("direct object")
    {
        test_pdf_proc(
            "<<"
            "/S /JavaScript"
            ">>",
            ""
        );
    }
    SECTION("indirect object")
    {
        test_pdf_proc(
            "19 0 obj"
            "<<"
            "/S /JavaScript"
            ">>"
            "endobj",
            ""
        );
    }
    SECTION("records")
    {
        test_pdf_proc(
            "1 0 R"
            "<<"
            "/T 2 0 R"
            ">>",
            ""
        );
    }
    SECTION("sub array")
    {
        test_pdf_proc(
            "<<"
            "/K [ /name1 /name2 /name3 ]"
            ">>",
            ""
        );
    }
    SECTION("sub dictionary")
    {
        test_pdf_proc(
            "<<"
            "/K << /k1 /v1 /k2 /v2 >> "
            ">>",
            ""
        );
    }
    SECTION("more items")
    {
        test_pdf_proc(
            "<00>"
            "<< >>"
            "<<"
            "/K << /k1 /v1 /k2 [ /i1 /i2 /i3 /i4 ] /k3 /v3 /k4 <000102> /k5 (abc) >>"
            ">>"
            "["
            "<</k1/v1/k2/v2/k3/v3>> <</k1[/i1/i2/i3[/j1/j2]]/k2<00>>> <</k1<</t1<00>>>>>"
            "]",
            ""
        );
    }
    SECTION("comments")
    {
        test_pdf_proc(
            "% comment 1\n"
            "<</K/V % comment /JS (script 1)\n>>"
            "<</K/V /JS (a % b)>>\n"
            "(% not a comment)\n"
            "% comment 2\n"
            "<</JS (; script 2) % comment 3\n>>",
            "a % b; script 2"
        );
    }
    SECTION("escapes in string")
    {
        test_pdf_proc(
            "(() \\n\\r\\t\\b\\f\\(\\)\\\\ \\123 \\A\\B\\C \\x\\y\\z)",
            ""
        );
    }
    SECTION("hex string")
    {
        test_pdf_proc(
            "<000102030405>",
            ""
        );
    }
    SECTION("key after literal string")
    {
        test_pdf_proc(
            "<<"
            "/Lang (EN-GB)"
            "/K [12 0 R]"
            ">>",
            ""
        );
    }
    SECTION("key after hex string")
    {
        test_pdf_proc(
            "<<"
            "/Lang <62617a>"
            "/K [12 0 R]"
            ">>",
            ""
        );
    }
    SECTION("number values")
    {
        test_pdf_proc(
            "<<"
            "/N 10"
            "/N 1.0"
            "/N 1."
            "/N .1"
            "/N 1"
            ">>",
            ""
        );
    }
    SECTION("not name for key")
    {
        test_pdf_proc(
            "<<"
            "/K1 /V1"
            "[/K2] /V2"
            "/K3 /V3"
            ">>",
            "",  PDFTokenizer::PDFRet::NOT_NAME_IN_DICTIONARY_KEY
        );
    }
    SECTION("literal string as a key")
    {
        test_pdf_proc(
            "<<"
            "/K1 /V1"
            "(foo) /V2"
            "/K3 /V3"
            ">>",
            "",  PDFTokenizer::PDFRet::NOT_NAME_IN_DICTIONARY_KEY
        );
    }
    SECTION("hex string as a key")
    {
        test_pdf_proc(
            "<<"
            "/K1 /V1"
            "<62617a> /V2"
            "/K3 /V3"
            ">>",
            "",  PDFTokenizer::PDFRet::NOT_NAME_IN_DICTIONARY_KEY
        );
    }
    SECTION("incomplete array")
    {
        test_pdf_proc(
            "<<"
            "/K1 [ /V1 /V2 /V3 "
            ">>",
            "",  PDFTokenizer::PDFRet::INCOMPLETE_ARRAY_IN_DICTIONARY
        );
    }
}

TEST_CASE("JS location", "[PDFTokenizer]")
{
    SECTION("wrong type")
    {
        test_pdf_proc(
            "<</S /JavaScript /JS /script >>",
            ""
        );
    }
    SECTION("no sub-type")
    {
        test_pdf_proc(
            "<< /JS (script) >>",
            "script"
        );
    }
    SECTION("no sub-type checks")
    {
        test_pdf_proc(
            "<< /JS (script) /S /JavaScript >>",
            "script"
        );
    }
    SECTION("no spaces")
    {
        test_pdf_proc(
            "<</S/JavaScript/JS(script)>>",
            "script"
        );
    }
    SECTION("as hex string")
    {
        test_pdf_proc(
            "<< /JS <62617a> >>",
            "baz"
        );
        test_pdf_proc(
            "<< /JS <70> >>",
            "p"
        );
        test_pdf_proc(
            "<< /JS <7> >>",
            "p"
        );
    }
    SECTION("prepended with records")
    {
        test_pdf_proc(
            "<</A 10 0 R /B 11 1 R/S/JavaScript/JS(script)>>",
            "script"
        );
    }
}

TEST_CASE("JS processing", "[PDFTokenizer]")
{
    SECTION("simple text")
    {
        test_pdf_proc(
            "<</JS"
            "(var _abc1 = 'Hello World!';)"
            ">>",
            "var _abc1 = 'Hello World!';"
        );
    }
    SECTION("balanced parenthesis")
    {
        test_pdf_proc(
            "<</JS"
            "(function foo() { console.log(\"Hello world!\") })"
            ">>",
            "function foo() { console.log(\"Hello world!\") }"
        );
    }
    SECTION("with escapes")
    {
        test_pdf_proc(
            "<</JS"
            "(function bar\\(var x\\)\\r{\\r    console.log\\(\"baz\"\\)\\r})"
            ">>",
            "function bar(var x)\r{\r    console.log(\"baz\")\r}"
        );
    }
    SECTION("all escapes")
    {
        test_pdf_proc(
            "<</JS"
            "(() \\n\\r\\t\\b\\f\\(\\)\\\\ \\123 \\A\\B\\C \\x\\y\\z)"
            ">>",
            "() \n\r\t\b\f()\\ \123 ABC xyz"
        );
    }
    SECTION("escaped new line")
    {
        test_pdf_proc(
            "<</JS"
            "(var str = 'Hello\\\n , \\\r    world\\\r\n\t!';)"
            ">>",
            "var str = 'Hello, world!';"
        );
    }
}

TEST_CASE("split", "[PDFTokenizer]")
{
    SECTION("no input")
    {
        test_pdf_proc({
            {"", ""},
            {"", ""},
            {"", ""}
        });
    }
    SECTION("minimal PDF")
    {
        test_pdf_proc({
            {"20 0 obj", ""},
            {"<<", ""},
            {"/Creator (Acrobat Pro DC 22.1.20169)", ""},
            {"/ModDate (D:20220714154535+03'00')", ""},
            {"/CreationDate (D:20220714153909+03'00')", ""},
            {"/Producer (Acrobat Pro DC 22.1.20169)", ""},
            {">>", ""},
            {"endobj", ""}
        });
    }
    SECTION("script")
    {
        test_pdf_proc({
            {"% comment", ""},
            {"\n", ""},
            {"<</K/V /JS (a % b)>>\n", "a % b"},
            {"(% not a", ""},
            {"comment)\n", ""},
            {"<</JS (;", ";"},
            {"script 2)", "script 2"},
            {">>", ""},
            {"<</JS(script 3)>>", "script 3"}
        });
    }
}
