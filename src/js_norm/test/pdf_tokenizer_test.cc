//--------------------------------------------------------------------------
// Copyright (C) 2022-2023 Cisco and/or its affiliates. All rights reserved.
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
using namespace std::string_literals;

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

        in.str(src);
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
            "1 0 obj\n"
            "% comment 1\n"
            "<</K/V % comment /JS (script 1)\n>>"
            "<</K/V % comment\r /JS (script 2; )\n>>"
            "<</K/V /JS (a % b; )>>\n"
            "% comment 2\n"
            "<</JS (script 3) % comment 3\n>>"
            "(% not a comment)\n"
            "endobj\n",
            "script 2; a % b; script 3"
        );
    }
    SECTION("escapes in string")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<< /S (() \\n\\r\\t\\b\\f\\(\\)\\\\ \\123 \\A\\B\\C \\x\\y\\z \\\n \\\r\n) >>\n"
            "endobj\n",
            ""
        );
    }
    SECTION("EOL in string")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<< /S (\r\n) >>\n"
            "endobj\n",
            ""
        );
    }
    SECTION("hex string")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<< /S <0001020304 05> >> \n"
            "endobj\n",
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
            "1 0 obj"
            "<<"
            "/K1 /V1"
            "[/K2] /V2"
            "/K3 /V3"
            ">>"
            "endobj",
            "",  PDFTokenizer::PDFRet::NOT_NAME_IN_DICTIONARY_KEY
        );
    }
    SECTION("literal string as a key")
    {
        test_pdf_proc(
            "1 0 obj"
            "<<"
            "/K1 /V1"
            "(foo) /V2"
            "/K3 /V3"
            ">>"
            "endobj",
            "",  PDFTokenizer::PDFRet::NOT_NAME_IN_DICTIONARY_KEY
        );
    }
    SECTION("hex string as a key")
    {
        test_pdf_proc(
            "1 0 obj"
            "<<"
            "/K1 /V1"
            "<62617a> /V2"
            "/K3 /V3"
            ">>"
            "endobj",
            "",  PDFTokenizer::PDFRet::NOT_NAME_IN_DICTIONARY_KEY
        );
    }
    SECTION("incomplete array")
    {
        test_pdf_proc(
            "1 0 obj"
            "<<"
            "/K1 [ /V1 /V2 /V3 "
            ">>"
            "endobj",
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
            "1 0 obj\n<< /JS (script) >>",
            "script"
        );
    }
    SECTION("no sub-type checks")
    {
        test_pdf_proc(
            "1 0 obj\n<< /JS (script) /S /JavaScript >>",
            "script"
        );
    }
    SECTION("no spaces")
    {
        test_pdf_proc(
            "1 0 obj\n<</S/JavaScript/JS(script)>>",
            "script"
        );
    }
    SECTION("as hex string")
    {
        test_pdf_proc(
            "1 0 obj\n<< /JS <62617a> >>",
            "baz"
        );
        test_pdf_proc(
            "1 0 obj\n<< /JS <70> >>",
            "p"
        );
        test_pdf_proc(
            "1 0 obj\n<< /JS <7> >>",
            "p"
        );
    }
    SECTION("prepended with records")
    {
        test_pdf_proc(
            "1 0 obj\n<</A 10 0 R /B 11 1 R/S/JavaScript/JS(script)>>",
            "script"
        );
    }
}

TEST_CASE("JS processing", "[PDFTokenizer]")
{
    SECTION("simple text")
    {
        test_pdf_proc(
            "1 0 obj\n<</JS"
            "(var _abc1 = 'Hello World!';)"
            ">>",
            "var _abc1 = 'Hello World!';"
        );
    }
    SECTION("balanced parenthesis")
    {
        test_pdf_proc(
            "1 0 obj\n<</JS"
            "(function foo() { console.log(\"Hello world!\") })"
            ">>",
            "function foo() { console.log(\"Hello world!\") }"
        );
    }
    SECTION("with escapes")
    {
        test_pdf_proc(
            "1 0 obj\n<</JS"
            "(function bar\\(var x\\)\\r{\\r    console.log\\(\"baz\"\\)\\r})"
            ">>",
            "function bar(var x)\r{\r    console.log(\"baz\")\r}"
        );
    }
    SECTION("all escapes")
    {
        test_pdf_proc(
            "1 0 obj\n<</JS"
            "(() \\n\\r\\t\\b\\f\\(\\)\\\\ \\123 \\A\\B\\C \\x\\y\\z)"
            ">>",
            "() \n\r\t\b\f()\\ \123 ABC xyz"
        );
    }
    SECTION("escaped new line")
    {
        test_pdf_proc(
            "1 0 obj\n<</JS"
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
            {"\n1 0 obj\n", ""},
            {"<</K/V /JS (a % b)>>\n", "a % b"},
            {"endobj\n2 0 obj\n(% not a", ""},
            {"comment)\nendobj\n3 0 obj\n", ""},
            {"<</JS (;", ";"},
            {"script 2)", "script 2"},
            {">>\nendobj\n4 0 obj\n", ""},
            {"<</JS(script 3)>>\nendobj", "script 3"}
        });
    }
}

TEST_CASE("stream object", "[PDFTokenizer]")
{
    SECTION("zero length")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 0 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "<<"
            "/Length 0"
            ">>"
            "stream\n"
            "\n"
            "endstream\n"
            "endobj\n",
            "\n"
        );
    }
    SECTION("exact length")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 0 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "<<"
            "/Length 6\n"
            ">>\n"
            "stream\n"
            "foobar\n"
            "endstream\n"
            "endobj\n",
            "foobar\n"
        );
    }
    SECTION("carriage return and line feed as EOL")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 0 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "<<"
            "/Length 3\n"
            ">>"
            "stream\r\n"
            "bar\r\n"
            "endstream\n"
            "endobj\n",
            "bar\n"
        );
    }
    SECTION("special symbols in a stream")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 0 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "<<"
            "/Length 13\n"
            ">>"
            "stream\n"
            "\nendstream\n \r\n"
            "endstream\n"
            "endobj\n",
            "\nendstream\n \n"
        );
    }
    SECTION("referenced JavaScript")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 0 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "<<"
            "/Length 9\n"
            ">>"
            "stream\n"
            "var a = 0\n"
            "endstream\n"
            "endobj\n",
            "var a = 0\n"
        );
    }
    SECTION("referenced JavaScript after another stream")
    {
        test_pdf_proc(
           "1 0 obj\n"
           "<</S /JavaScript /JS 2 0 R>>\n"
           "endobj\n"
           "3 0 obj\n"
           "<</Length 1>>\n"
           "stream\n"
           " \n"
           "endstream\n"
           "endobj\n"
           "2 0 obj\n"
           "<<"
           "/Length 9\n"
           ">>"
           "stream\n"
           "var a = 0\n"
           "endstream\n"
           "endobj\n",
           "var a = 0\n"
        );
    }
    SECTION("multiple revisions")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 1 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "<</Length 13>>\n"
            "stream\n"
            "//revision 1\n\n"
            "endstream\n"
            "endobj\n"
            "2 1 obj\n"
            "<</Length 13>>\n"
            "stream\n"
            "//revision 2\n\n"
            "endstream\n"
            "endobj\n",
            "//revision 1\n\n"
            "//revision 2\n\n"
        );
    }
}

TEST_CASE("stream object malformed", "[PDFTokenizer]")
{
    SECTION("no dictionary")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 0 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "stream\n"
            "foo\n"
            "endstream\n"
            "endobj\n",
            "", PDFTokenizer::PDFRet::STREAM_NO_LENGTH
        );
    }
    SECTION("a direct stream")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 0 R>>\n"
            "endobj\n"
            "<<"
            "/Length 3"
            ">>\n"
            "stream\n"
            "foo\n"
            "endstream\n",
            "", PDFTokenizer::PDFRet::EOS
        );
    }
    SECTION("an indirect dictionary")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 3 0 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "<<"
            "/Length 3"
            ">>\n"
            "endobj\n"
            "3 0 obj\n"
            "2 0 R\n"
            "stream\n"
            "foo\n"
            "endstream\n"
            "endobj\n",
            "", PDFTokenizer::PDFRet::UNEXPECTED_SYMBOL
        );
    }
    SECTION("no length")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 0 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "<<"
            "/Creator (Acrobat Pro DC 22.1.20169)"
            ">>\n"
            "stream\n"
            "foo\n"
            "endstream\n"
            "endobj\n",
            "", PDFTokenizer::PDFRet::STREAM_NO_LENGTH
        );
    }
    SECTION("length less")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 0 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "<<"
            "/Length 2"
            ">>\n"
            "stream\n"
            "foo\n"
            "endstream\n"
            "endobj\n",
            "foo\n", PDFTokenizer::PDFRet::EOS
        );
    }
    SECTION("length greater within a few bytes")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 0 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "<<"
            "/Length 4"
            ">>\n"
            "stream\n"
            "foo\n"
            "endstream\n"
            "endobj\n",
            "foo\n", PDFTokenizer::PDFRet::EOS
            // note that '\n' in expected is not extracted from source data.
            // preprocessor does not extract exactly "/Length" bytes, and as long
            // as length is greater by no more than a few bytes stream will be read
            // correctly up to endstream marker.
        );
    }
    SECTION("length greater")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 0 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "<<"
            "/Length 100"
            ">>\n"
            "stream\n"
            "foo\n"
            "endstream\n"
            "endobj\n",
            "foo\n"
            "endstream\n"
            "endobj\n", PDFTokenizer::PDFRet::EOS
        );
    }
    SECTION("carriage return following the keyword stream")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 0 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "<<"
            "/Length 3"
            ">>\n"
            "stream\r"
            "foo\r"
            "endstream\n"
            "endobj\n",
            "", PDFTokenizer::PDFRet::UNEXPECTED_SYMBOL
        );
    }
    SECTION("no end-off-line marker specified")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 0 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "<<"
            "/Length 3"
            ">>\n"
            "stream"
            "foo"
            "endstream\n"
            "endobj\n",
            "", PDFTokenizer::PDFRet::UNEXPECTED_SYMBOL
        );
    }
    SECTION("no end-off-line marker in stream data")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<</S /JavaScript /JS 2 0 R>>\n"
            "endobj\n"
            "2 0 obj\n"
            "<<"
            "/Length 3"
            ">>\n"
            "stream\n"
            "foo"
            "endstream\n"
            "endobj\n",
            "fooendstream\n"
            "endobj\n", PDFTokenizer::PDFRet::EOS
        );
    }
}

TEST_CASE("stream object over PDU", "[PDFTokenizer]")
{
    SECTION("split inside non-JS stream")
    {
        test_pdf_proc({
            {
                "10 0 obj\n"
                "<</Length 6>>\n"
                "stream\n"
                "foo",
                ""
            },
            {
                "bar\n"
                "endstream\n"
                "endobj\n",
                ""
            }
        });
    }
    SECTION("split inside JavaScript stream")
    {
        test_pdf_proc({
            {
                "1 0 obj\n"
                "<</JS 10 0 R>>\n"
                "endobj\n"
                "10 0 obj\n"
                "<</Length 6>>\n"
                "stream\n"
                "foo",
                "foo"
            },
            {
                "bar\n"
                "endstream\n"
                "endobj\n",
                "bar\n"
            }
        });
    }
    SECTION("split between reference and stream obj")
    {
        test_pdf_proc({
            {
                "1 0 obj\n"
                "<</JS 10 0 R>>\n"
                "endobj\n",
                ""
            },
            {
                "10 0 obj\n"
                "<</Length 6>>\n"
                "stream\n"
                "foobar\n"
                "endstream\n"
                "endobj\n",
                "foobar\n"
            }
        });
    }
    SECTION("split between dictionary and stream")
    {
        test_pdf_proc({
            {
                "1 0 obj\n"
                "<</JS 10 0 R>>\n"
                "endobj\n"
                "10 0 obj\n"
                "<</Length 6>>\n",
                ""
            },
            {
                "stream\n"
                "foobar\n"
                "endstream\n"
                "endobj\n",
                "foobar\n"
            }
        });
    }
}

TEST_CASE("UTF-16, basic", "[PDFTokenizer]")
{
    SECTION("basic string")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS (\xfe\xff\0f\0o\0o)"s,
            "foo"s
        );
    }
    SECTION("non-ASCII character")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS (\xfe\xff\xd8=\xdc=)"s,
            "\xf0\x9f\x90\xbd"s
        );
    }
    SECTION("Latin-1 character")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS (\xfe\xff\0\xc6)"s,
            "\xc3\x86"s
        );
    }
    SECTION("mixed charset")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS (\xfe\xff\0f\0o\0o\xd8=\xdc=\0\x20\0b\0a\0r)"s,
            "foo\xf0\x9f\x90\xbd bar"s
        );
    }
    SECTION("stream")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS 2 0 R"
            ">>\n"
            "endobj\n"
            "2 0 obj\n"
            "<</Length 8>>\n"
            "stream\n"
            "\xfe\xff\0f\0o\0o\n"
            "endstream\n"
            "endobj"s,
            "foo"s
        );
    }
    SECTION("hexadecimal string")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS <FE FF 00 66 006F 00 6F>"s,
            "foo"s
        );
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS <FE FF 00 66 006F 00 6F 00 2>"s,
            "foo "s
        );
    }
    SECTION("escaped slash")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS (\xfe\xff\0\\\\\0f\0o\0o)"s,
            "\\foo"s
        );
    }
    SECTION("escaped slash-like byte of a CJK character")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS (\xfe\xff\\\\\0)"s,
            "\xe5\xb0\x80"s
        );
    }
    SECTION("newline: CR")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS (\xfe\xff\0f\0o\0o\0\r\0b\0a\0r)"s,
            "foo\r"
            "bar"s
        );
    }
    SECTION("newline: LF")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS (\xfe\xff\0f\0o\0o\0\n\0b\0a\0r)"s,
            "foo\n"
            "bar"s
        );
    }
    SECTION("escaped newline: CR")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS (\xfe\xff\0f\0o\0o\0\\r\0b\0a\0r)"s,
            "foo\r"
            "bar"s
        );
    }
    SECTION("escaped newline: LF")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS (\xfe\xff\0f\0o\0o\0\\n\0b\0a\0r)"s,
            "foo\n"
            "bar"s
        );
    }
    SECTION("escaped newline: PDF line wrap")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS (\xfe\xff\0f\0o\0o\\\n"
            "\0b\0a\0r)"s,
            "foobar"s
        );
    }
    SECTION("slash in stream")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS 2 0 R"
            ">>\n"
            "endobj\n"
            "2 0 obj\n"
            "<</Length 8>>\n"
            "stream\n"
            "\xfe\xff\0\\\0f\0o\0o\n"
            "endstream\n"
            "endobj"s,
            "\\foo"s
        );
    }
    SECTION("unexpected symbol")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS (\xfe\xff\0\\(\0a\0()"s,
            "(a"s,
            PDFTokenizer::PDFRet::UNEXPECTED_SYMBOL
        );
    }
    SECTION("invalid high surrogate pair")
    {
        test_pdf_proc(
            "1 0 obj\n"
            "<<"
            "/S /JavaScript"
            "/JS (\xfe\xff\xd8=\0=)"s,
            ""s,
            PDFTokenizer::PDFRet::UNEXPECTED_SYMBOL
        );
    }
}

TEST_CASE("UTF-16, cross-PDU", "[PDFTokenizer]")
{
    SECTION("split between symbols")
    {
        test_pdf_proc({
            {
                "10 0 obj\n"
                "<</S/JavaScript/JS(\xfe\xff\0f\0o\0o"s,
                "foo"s
            },
            {
                "\0b\0a\0r)>>\n"
                "endobj"s,
                "bar"s
            }
        });
    }
    SECTION("split inside the symbol between code units")
    {
        test_pdf_proc({
            {
                "10 0 obj\n"
                "<</S/JavaScript/JS(\xfe\xff\xd8="s,
                ""s
            },
            {
                "\xdc=)>>\n"
                "endobj"s,
                "\xf0\x9f\x90\xbd"s
            }
        });
    }
    SECTION("split inside the code unit")
    {
        test_pdf_proc({
            {
                "10 0 obj\n"
                "<</S/JavaScript/JS(\xfe\xff\xd8"s,
                ""s
            },
            {
                "=\xdc=)>>\n"
                "endobj"s,
                "\xf0\x9f\x90\xbd"s
            }
        });
    }
    SECTION("split inside escaped slash: first byte escaped")
    {
        test_pdf_proc({
            {
                "10 0 obj\n"
                "<</S/JavaScript/JS(\xfe\xff\\\\"s,
                ""s
            },
            {
                "\0)>>\n"
                "endobj"s,
                "\xe5\xb0\x80"s
            }
        });
    }
    SECTION("split in hexadecimal string")
    {
        test_pdf_proc({
            {
                "10 0 obj\n"
                "<</S/JavaScript/JS<FEFF 00"s,
                ""s
            },
            {
                "66 00 6F 00 6F>>>\n"
                "endobj"s,
                "foo"s
            }
        });
    }
    SECTION("split in stream")
    {
        test_pdf_proc({
            {
                "1 0 obj\n"
                "<</S/JavaScript/JS 2 0 R>>\n"
                "endobj\n"
                "2 0 obj\n"
                "<</Length 14>>\n"
                "stream\n"
                "\xfe\xff\0f\0o\0o\0"s,
                "foo"s
            },
            {
                "b\0a\0r\n"
                "endstream\n"
                "endobj"s,
                "bar"s
            }
        });
    }
}
