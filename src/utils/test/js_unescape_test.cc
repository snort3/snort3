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
// js_unescape_test.cc author Volodymyr Horban <vhorban@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/catch.hpp"

#include "utils/js_identifier_ctx.h"
#include "utils/js_normalizer.h"

#include "js_test_utils.h"

#ifdef CATCH_TEST_BUILD

TEST_CASE("Sequence parsing", "[JSNormalizer]")
{
    SECTION("\\xXX")
    {
        test_normalization(
            "'\\x01'",
            "'\u0001'"
        );
        test_normalization(
            "'\\x23'",
            "'\u0023'"
        );
        test_normalization(
            "'\\x45'",
            "'\u0045'"
        );
        test_normalization(
            "'\\x67'",
            "'\u0067'"
        );
        test_normalization(
            "'\\x89'",
            "'\u0089'"
        );
        test_normalization(
            "'\\xaA'",
            "'\u00aA'"
        );
        test_normalization(
            "'\\xbB'",
            "'\u00bB'"
        );
        test_normalization(
            "'\\xcC'",
            "'\u00cC'"
        );
        test_normalization(
            "'\\xdD'",
            "'\u00dD'"
        );
        test_normalization(
            "'\\xeE'",
            "'\u00eE'"
        );
        test_normalization(
            "'\\xfF'",
            "'\u00fF'"
        );
    }

    SECTION("\\uXXXX")
    {
        test_normalization(
            "'\\u0123'",
            "'\u0123'"
        );
        test_normalization(
            "'\\u4567'",
            "'\u4567'"
        );
        test_normalization(
            "'\\u89aA'",
            "'\u89aA'"
        );
        test_normalization(
            "'\\ubBcC'",
            "'\ubBcC'"
        );
        test_normalization(
            "'\\ueEfF'",
            "'\ueEfF'"
        );
    }

    SECTION("\\u{XXXX}")
    {
        test_normalization(
            "'\\u{0123}'",
            "'\u0123'"
        );
        test_normalization(
            "'\\u{4567}'",
            "'\u4567'"
        );
        test_normalization(
            "'\\u{89aA}'",
            "'\u89aA'"
        );
        test_normalization(
            "'\\u{bBcC}'",
            "'\ubBcC'"
        );
        test_normalization(
            "'\\u{eEfF}'",
            "'\ueEfF'"
        );
    }

    SECTION("%XX")
    {
        test_normalization(
            "unescape('%01')",
            "'\u0001'"
        );
        test_normalization(
            "unescape('%23')",
            "'\u0023'"
        );
        test_normalization(
            "unescape('%45')",
            "'\u0045'"
        );
        test_normalization(
            "unescape('%67')",
            "'\u0067'"
        );
        test_normalization(
            "unescape('%89')",
            "'\u0089'"
        );
        test_normalization(
            "unescape('%aA')",
            "'\u00aA'"
        );
        test_normalization(
            "unescape('%bB')",
            "'\u00bB'"
        );
        test_normalization(
            "unescape('%cC')",
            "'\u00cC'"
        );
        test_normalization(
            "unescape('%dD')",
            "'\u00dD'"
        );
        test_normalization(
            "unescape('%eE')",
            "'\u00eE'"
        );
        test_normalization(
            "unescape('%fF')",
            "'\u00fF'"
        );
    }

    SECTION("\\uXX")
    {
        test_normalization(
            "unescape('\\u01')",
            "'\u0001'"
        );
        test_normalization(
            "unescape('%23')",
            "'\u0023'"
        );
        test_normalization(
            "unescape('\\u45')",
            "'\u0045'"
        );
        test_normalization(
            "unescape('\\u67')",
            "'\u0067'"
        );
        test_normalization(
            "unescape('\\u89')",
            "'\u0089'"
        );
        test_normalization(
            "unescape('\\uaA')",
            "'\u00aA'"
        );
        test_normalization(
            "unescape('\\ubB')",
            "'\u00bB'"
        );
        test_normalization(
            "unescape('\\ucC')",
            "'\u00cC'"
        );
        test_normalization(
            "unescape('\\udD')",
            "'\u00dD'"
        );
        test_normalization(
            "unescape('\\ueE')",
            "'\u00eE'"
        );
        test_normalization(
            "unescape('\\ufF')",
            "'\u00fF'"
        );
    }

    SECTION("%uXXXX")
    {
        test_normalization(
            "unescape('%u0123')",
            "'\u0123'"
        );
        test_normalization(
            "unescape('%u4567')",
            "'\u4567'"
        );
        test_normalization(
            "unescape('%u89aA')",
            "'\u89aA'"
        );
        test_normalization(
            "unescape('%ubBcC')",
            "'\ubBcC'"
        );
        test_normalization(
            "unescape('%ueEfF')",
            "'\ueEfF'"
        );
    }

    SECTION("decimal")
    {
        test_normalization(
            "String.fromCharCode(1)",
            "'\u0001'"
        );
        test_normalization(
            "String.fromCharCode(12)",
            "'\u000c'"
        );
        test_normalization(
            "String.fromCharCode(345)",
            "'\u0159'"
        );
        test_normalization(
            "String.fromCharCode(6789)",
            "'\u1a85'"
        );
        test_normalization(
            "String.fromCharCode(1000)",
            "'\u03e8'"
        );
        test_normalization(
            "String.fromCharCode(0001)",
            "'\x01'"
        );
        test_normalization(
            "String.fromCharCode(65536)",
            "'\xf0\x90\x80\x80'"
        );
        test_normalization(
            "String.fromCodePoint(2097152)",
            "'\xf7\xbf\xbf\xbf'"
        );
    }

    SECTION("hexadecimal")
    {
        test_normalization(
            "String.fromCharCode(0x0001)",
            "'\u0001'"
        );
        test_normalization(
            "String.fromCharCode(0X0001)",
            "'\u0001'"
        );
        test_normalization(
            "String.fromCharCode(0x1234)",
            "'\u1234'"
        );
        test_normalization(
            "String.fromCharCode(0X5678)",
            "'\u5678'"
        );
        test_normalization(
            "String.fromCharCode(0x9aAb)",
            "'\u9aAb'"
        );
        test_normalization(
            "String.fromCharCode(0x9aAb)",
            "'\u9aAb'"
        );
        test_normalization(
            "String.fromCharCode(0xBcCd)",
            "'\uBcCd'"
        );
        test_normalization(
            "String.fromCharCode(0XeEfF)",
            "'\ueEfF'"
        );
        test_normalization(
            "String.fromCodePoint(0x10000)",
            "'\xf0\x90\x80\x80'"
        );
        test_normalization(
            "String.fromCharCode(0X10000)",
            "'\xf0\x90\x80\x80'"
        );
        test_normalization(
            "String.fromCodePoint(0x200000)",
            "'\xf7\xbf\xbf\xbf'"
        );
        test_normalization(
            "String.fromCodePoint(0X200000)",
            "'\xf7\xbf\xbf\xbf'"
        );
    }
}

TEST_CASE("Universal sequences", "[JSNormalizer]")
{
    SECTION("\\uXXXX")
    {
        test_normalization(
            "\\u0065\\u0076\\u0061\\u006C () ;",
            "eval();"
        );
        test_normalization(
            "'\\u0062\\u0061\\u0072'",
            "'bar'"
        );
        test_normalization(
            "\"\\u0062\\u0061\\u0072\"",
            "\"bar\""
        );
        test_normalization(
            "`\\u0062\\u0061\\u0072`",
            "`bar`"
        );
        test_normalization(
            "/\\u0062\\u0061\\u0072/",
            "/bar/"
        );
    }

    SECTION("\\xXX")
    {
        test_normalization(
            "'\\x62\\x61\\x72'",
            "'bar'"
        );
        test_normalization(
            "\"\\x62\\x61\\x72\"",
            "\"bar\""
        );
        test_normalization(
            "`\\x62\\x61\\x72`",
            "`bar`"
        );
        test_normalization(
            "/\\x62\\x61\\x72/",
            "/bar/"
        );
    }

    SECTION("\\u{XXXX}")
    {
        test_normalization(
            "\\u{0065}\\u{0076}\\u{0061}\\u{006C} () ;",
            "eval();"
        );
        test_normalization(
            "'\\u{0062}\\u{0061}\\u{0072}'",
            "'bar'"
        );
        test_normalization(
            "\"\\u{0062}\\u{0061}\\u{0072}\"",
            "\"bar\""
        );
        test_normalization(
            "`\\u{0062}\\u{0061}\\u{0072}`",
            "`bar`"
        );
    }
}

TEST_CASE("unescape()", "[JSNormalizer]")
{
    SECTION("%XX")
    {
        test_normalization(
            "unescape('%62%61%72')",
            "'bar'"
        );
        test_normalization(
            "unescape(\"%62%61%72\")",
            "\"bar\""
        );
        test_normalization(
            "unescape(`%62%61%72`)",
            "`bar`"
        );
    }

    SECTION("%uXXXX")
    {
        test_normalization(
            "unescape('%u0062%u0061%u0072')",
            "'bar'"
        );
        test_normalization(
            "unescape(\"%u0062%u0061%u0072\")",
            "\"bar\""
        );
        test_normalization(
            "unescape(`%u0062%u0061%u0072`)",
            "`bar`"
        );
    }

    SECTION("\\uXX")
    {
        test_normalization(
            "unescape('\\u62\\u61\\u72')",
            "'bar'"
        );
        test_normalization(
            "unescape(\"\\u62\\u61\\u72\")",
            "\"bar\""
        );
        test_normalization(
            "unescape(`\\u62\\u61\\u72`)",
            "`bar`"
        );
    }

    SECTION("\\uXXXX")
    {
        test_normalization(
            "unescape('\\u0062\\u0061\\u0072')",
            "'bar'"
        );
        test_normalization(
            "unescape(\"\\u0062\\u0061\\u0072\")",
            "\"bar\""
        );
        test_normalization(
            "unescape(`\\u0062\\u0061\\u0072`)",
            "`bar`"
        );
    }

    SECTION("\\xXX")
    {
        test_normalization(
            "unescape('\\x62\\x61\\x72')",
            "'bar'"
        );
        test_normalization(
            "unescape(\"\\x62\\x61\\x72\")",
            "\"bar\""
        );
        test_normalization(
            "unescape(`\\x62\\x61\\x72`)",
            "`bar`"
        );
    }

    SECTION("\\u{XXXX}")
    {
        test_normalization(
            "unescape('\\u{0062}\\u{0061}\\u{0072}')",
            "'bar'"
        );
        test_normalization(
            "unescape(\"\\u{0062}\\u{0061}\\u{0072}\")",
            "\"bar\""
        );
        test_normalization(
            "unescape(`\\u{0062}\\u{0061}\\u{0072}`)",
            "`bar`"
        );
    }

    SECTION("mixed sequence")
    {
        test_normalization_mixed_encoding(
            "unescape('\\u62%61%72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "unescape('\\x62%u0061%72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "unescape('\\x62\\u61\\u72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "unescape('%u0062\\u0061%72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "unescape('\\u0062\\x61%72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "unescape('\\u0062\\u{0061}\\x72')",
            "'bar'"
        );
    }
}

TEST_CASE("decodeURI()", "[JSNormalizer]")
{
    SECTION("%XX")
    {
        test_normalization(
            "decodeURI('%62%61%72')",
            "'bar'"
        );
        test_normalization(
            "decodeURI(\"%62%61%72\")",
            "\"bar\""
        );
        test_normalization(
            "decodeURI(`%62%61%72`)",
            "`bar`"
        );
    }

    SECTION("%uXXXX")
    {
        test_normalization(
            "decodeURI('%u0062%u0061%u0072')",
            "'bar'"
        );
        test_normalization(
            "decodeURI(\"%u0062%u0061%u0072\")",
            "\"bar\""
        );
        test_normalization(
            "decodeURI(`%u0062%u0061%u0072`)",
            "`bar`"
        );
    }

    SECTION("\\uXX")
    {
        test_normalization(
            "decodeURI('\\u62\\u61\\u72')",
            "'bar'"
        );
        test_normalization(
            "decodeURI(\"\\u62\\u61\\u72\")",
            "\"bar\""
        );
        test_normalization(
            "decodeURI(`\\u62\\u61\\u72`)",
            "`bar`"
        );
    }

    SECTION("\\uXXXX")
    {
        test_normalization(
            "decodeURI('\\u0062\\u0061\\u0072')",
            "'bar'"
        );
        test_normalization(
            "decodeURI(\"\\u0062\\u0061\\u0072\")",
            "\"bar\""
        );
        test_normalization(
            "decodeURI(`\\u0062\\u0061\\u0072`)",
            "`bar`"
        );
    }

    SECTION("\\xXX")
    {
        test_normalization(
            "decodeURI('\\x62\\x61\\x72')",
            "'bar'"
        );
        test_normalization(
            "decodeURI(\"\\x62\\x61\\x72\")",
            "\"bar\""
        );
        test_normalization(
            "decodeURI(`\\x62\\x61\\x72`)",
            "`bar`"
        );
    }

    SECTION("\\u{XXXX}")
    {
        test_normalization(
            "decodeURI('\\u{0062}\\u{0061}\\u{0072}')",
            "'bar'"
        );
        test_normalization(
            "decodeURI(\"\\u{0062}\\u{0061}\\u{0072}\")",
            "\"bar\""
        );
        test_normalization(
            "decodeURI(`\\u{0062}\\u{0061}\\u{0072}`)",
            "`bar`"
        );
    }

    SECTION("mixed sequence")
    {
        test_normalization_mixed_encoding(
            "decodeURI('\\u62%61%72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "decodeURI('\\x62%u0061%72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "decodeURI('\\x62\\u61\\u72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "decodeURI('%u0062\\u0061%72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "decodeURI('\\u0062\\x61%72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "decodeURI('\\u0062\\u{0061}\\x72')",
            "'bar'"
        );
    }
}

TEST_CASE("decodeURIComponent()", "[JSNormalizer]")
{
    SECTION("%XX")
    {
        test_normalization(
            "decodeURIComponent('%62%61%72')",
            "'bar'"
        );
        test_normalization(
            "decodeURIComponent(\"%62%61%72\")",
            "\"bar\""
        );
        test_normalization(
            "decodeURIComponent(`%62%61%72`)",
            "`bar`"
        );
    }

    SECTION("%uXXXX")
    {
        test_normalization(
            "decodeURIComponent('%u0062%u0061%u0072')",
            "'bar'"
        );
        test_normalization(
            "decodeURIComponent(\"%u0062%u0061%u0072\")",
            "\"bar\""
        );
        test_normalization(
            "decodeURIComponent(`%u0062%u0061%u0072`)",
            "`bar`"
        );
    }

    SECTION("\\uXX")
    {
        test_normalization(
            "decodeURIComponent('\\u62\\u61\\u72')",
            "'bar'"
        );
        test_normalization(
            "decodeURIComponent(\"\\u62\\u61\\u72\")",
            "\"bar\""
        );
        test_normalization(
            "decodeURIComponent(`\\u62\\u61\\u72`)",
            "`bar`"
        );
    }

    SECTION("\\uXXXX")
    {
        test_normalization(
            "decodeURIComponent('\\u0062\\u0061\\u0072')",
            "'bar'"
        );
        test_normalization(
            "decodeURIComponent(\"\\u0062\\u0061\\u0072\")",
            "\"bar\""
        );
        test_normalization(
            "decodeURIComponent(`\\u0062\\u0061\\u0072`)",
            "`bar`"
        );
    }

    SECTION("\\xXX")
    {
        test_normalization(
            "decodeURIComponent('\\x62\\x61\\x72')",
            "'bar'"
        );
        test_normalization(
            "decodeURIComponent(\"\\x62\\x61\\x72\")",
            "\"bar\""
        );
        test_normalization(
            "decodeURIComponent(`\\x62\\x61\\x72`)",
            "`bar`"
        );
    }

    SECTION("\\u{XXXX}")
    {
        test_normalization(
            "decodeURIComponent('\\u{0062}\\u{0061}\\u{0072}')",
            "'bar'"
        );
        test_normalization(
            "decodeURIComponent(\"\\u{0062}\\u{0061}\\u{0072}\")",
            "\"bar\""
        );
        test_normalization(
            "decodeURIComponent(`\\u{0062}\\u{0061}\\u{0072}`)",
            "`bar`"
        );
    }

    SECTION("mixed sequence")
    {
        test_normalization_mixed_encoding(
            "decodeURIComponent('\\u62%61%72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "decodeURIComponent('\\x62%u0061%72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "decodeURIComponent('\\x62\\u61\\u72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "decodeURIComponent('%u0062\\u0061%72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "decodeURIComponent('\\u0062\\x61%72')",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "decodeURIComponent('\\u0062\\u{0061}\\x72')",
            "'bar'"
        );
    }
}

TEST_CASE("String.fromCharCode()", "[JSNormalizer]")
{
    SECTION("decimal")
    {
        test_normalization(
            "String.fromCharCode(98, 97, 114)",
            "'bar'"
        );
    }

    SECTION("hexadecimal")
    {
        test_normalization(
            "String.fromCharCode(0x62, 0x61, 0x72)",
            "'bar'"
        );

        test_normalization(
            "String.fromCharCode(0x0062, 0x0061, 0x0072)",
            "'bar'"
        );
    }

    SECTION("mixed sequence")
    {
        test_normalization_mixed_encoding(
            "String.fromCharCode(98, 97, 0x72)",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "String.fromCharCode(0x62, 97, 114)",
            "'bar'"
        );
    }
}

TEST_CASE("String.fromCodePoint()", "[JSNormalizer]")
{
    SECTION("decimal")
    {
        test_normalization(
            "String.fromCodePoint(98, 97, 114)",
            "'bar'"
        );

        test_normalization(
            "String.fromCodePoint(65600, 65601, 65602)",
            "'\xf0\x90\x81\x80\xf0\x90\x81\x81\xf0\x90\x81\x82'"
        );
    }

    SECTION("hexadecimal")
    {
        test_normalization(
            "String.fromCodePoint(0x62, 0x61, 0x72)",
            "'bar'"
        );

        test_normalization(
            "String.fromCodePoint(0x00000062, 0x00000061, 0x00000072)",
            "'bar'"
        );

        test_normalization(
            "String.fromCodePoint(0x10040, 0x10041, 0x10042)",
            "'\xf0\x90\x81\x80\xf0\x90\x81\x81\xf0\x90\x81\x82'"
        );
    }

    SECTION("mixed sequence")
    {
        test_normalization_mixed_encoding(
            "String.fromCodePoint(98, 97, 0x72)",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "String.fromCodePoint(0x00000062, 97, 114)",
            "'bar'"
        );

        test_normalization_mixed_encoding(
            "String.fromCodePoint(65600, 0x10041, 65602)",
            "'\xf0\x90\x81\x80\xf0\x90\x81\x81\xf0\x90\x81\x82'"
        );

        test_normalization_mixed_encoding(
            "String.fromCodePoint(0x10040, 65601, 0x10042)",
            "'\xf0\x90\x81\x80\xf0\x90\x81\x81\xf0\x90\x81\x82'"
        );
    }
}

TEST_CASE("Split", "[JSNormalizer]")
{
    SECTION("unescape()")
    {
        test_normalization({
            { "unescape(", "" },
            { ")", "" }
        });

        test_normalization({
            { "unescape('%62", "'b" },
            { "%61%72')", "'bar'" }
        });

        test_normalization({
            { "unescape('%62%61", "'ba" },
            { "%72')", "'bar'" }
        });

        test_normalization({
            { "unescape('%62%61%72", "'bar" },
            { "')", "'bar'" }
        });

        test_normalization({
            { "unescape('%u", "'%u" },
            { "0062%u0061%u0072')", "'bar'" }
        });

        test_normalization({
            { "unescape('%u00", "'%u00" },
            { "62%u0061%u0072')", "'bar'" }
        });

        test_normalization({
            { "unescape('%u0062", "'b" },
            { "%u0061%u0072')", "'bar'" }
        });

        test_normalization({
            { "unescape('%u0062%u", "'b%u" },
            { "0061%u0072')", "'bar'" }
        });

        test_normalization({
            { "unescape('%u0062%u00", "'b%u00" },
            { "61%u0072')", "'bar'" }
        });

        test_normalization({
            { "unescape('%u0062%u0061", "'ba" },
            { "%u0072')", "'bar'" }
        });

        test_normalization({
            { "unescape('%u0062%u0061%u", "'ba%u" },
            { "0072')", "'bar'" }
        });

        test_normalization({
            { "unescape('%u0062%u0061%u00", "'ba%u00" },
            { "72')", "'bar'" }
        });

        test_normalization({
            { "unescape('%u0062%u0061%u0072", "'bar" },
            { "')", "'bar'" }
        });

        test_normalization({
            { "unescape('%u0062", "'b" },
            { "%u0061", "'ba" },
            { "%u0072')", "'bar'" }
        });
    }

    SECTION("decodeURI()")
    {
        test_normalization({
            { "decodeURI(", "" },
            { ")", "" }
        });

        test_normalization({
            { "decodeURI('%u", "'%u" },
            { "0062%u0061%u0072')", "'bar'" }
        });

        test_normalization({
            { "decodeURI('%u00", "'%u00" },
            { "62%u0061%u0072')", "'bar'" }
        });

        test_normalization({
            { "decodeURI('%u0062%u", "'b%u" },
            { "0061%u0072')", "'bar'" }
        });

        test_normalization({
            { "decodeURI('%u0062%u00", "'b%u00" },
            { "61%u0072')", "'bar'" }
        });

        test_normalization({
            { "decodeURI('%u0062%u0061", "'ba" },
            { "%u0072')", "'bar'" }
        });

        test_normalization({
            { "decodeURI('%u0062%u0061%u", "'ba%u" },
            { "0072')", "'bar'" }
        });

        test_normalization({
            { "decodeURI('%u0062%u0061%u00", "'ba%u00" },
            { "72')", "'bar'" }
        });

        test_normalization({
            { "decodeURI('%u0062%u0061%u0072", "'bar" },
            { "')", "'bar'" }
        });

        test_normalization({
            { "decodeURI('%u0062", "'b" },
            { "%u0061", "'ba" },
            { "%u0072')", "'bar'" }
        });
    }

    SECTION("decodeURIComponent()")
    {
        test_normalization({
            { "decodeURIComponent(", "" },
            { ")", "" }
        });

        test_normalization({
            { "decodeURIComponent('%u", "'%u" },
            { "0062%u0061%u0072')", "'bar'" }
        });

        test_normalization({
            { "decodeURIComponent('%u00", "'%u00" },
            { "62%u0061%u0072')", "'bar'" }
        });

        test_normalization({
            { "decodeURIComponent('%u0062%u", "'b%u" },
            { "0061%u0072')", "'bar'" }
        });

        test_normalization({
            { "decodeURIComponent('%u0062%u00", "'b%u00" },
            { "61%u0072')", "'bar'" }
        });

        test_normalization({
            { "decodeURIComponent('%u0062%u0061", "'ba" },
            { "%u0072')", "'bar'" }
        });

        test_normalization({
            { "decodeURIComponent('%u0062%u0061%u", "'ba%u" },
            { "0072')", "'bar'" }
        });

        test_normalization({
            { "decodeURIComponent('%u0062%u0061%u00", "'ba%u00" },
            { "72')", "'bar'" }
        });

        test_normalization({
            { "decodeURIComponent('%u0062%u0061%u0072", "'bar" },
            { "')", "'bar'" }
        });

        test_normalization({
            { "decodeURIComponent('%u0062", "'b" },
            { "%u0061", "'ba" },
            { "%u0072')", "'bar'" }
        });
    }

    SECTION("String.fromCharCode()")
    {
        test_normalization({
            { "String.fromCharCode(", "'" },
            { ")", "''" }
        });

        test_normalization({
            { "String.fromCharCode(9", "'\u0009" },
            { "8, 97, 114)", "'bar'" }
        });

        test_normalization({
            { "String.fromCharCode(98,", "'b" },
            { "97, 114)", "'bar'" }
        });

        test_normalization({
            { "String.fromCharCode(98, 97", "'ba" },
            { ",114)", "'bar'" }
        });

        test_normalization({
            { "String.fromCharCode(98, 97, 114", "'bar" },
            { ")", "'bar'" }
        });

        test_normalization({
            { "String.fromCharCode(0x0062", "'b" },
            { ",0x0061, 0x0072)", "'bar'" }
        });

        test_normalization({
            { "String.fromCharCode(0x0062, 0x0061", "'ba" },
            { ", 0x0072)", "'bar'" }
        });

        test_normalization({
            { "String.fromCharCode(0x0062, 0x0061, 0x0072", "'bar" },
            { ")", "'bar'" }
        });

        test_normalization({
            { "String.fromCharCode(0x0062,", "'b" },
            { "0x0061,", "'ba" },
            { "0x72)",   "'bar'" }
        });

        test_normalization({
            { "String.fromCharCode(98,", "'b" },
            { "97,", "'ba" },
            { "114)", "'bar'" }
        });
    }

    SECTION("String.fromCodePoint()")
    {
        test_normalization({
            { "String.fromCodePoint(", "'" },
            { ")", "''" }
        });

        test_normalization({
            { "String.fromCodePoint(9", "'\u0009" },
            { "8, 97, 114)", "'bar'" }
        });

        test_normalization({
            { "String.fromCodePoint(98,", "'b" },
            { "97, 114)", "'bar'" }
        });

        test_normalization({
            { "String.fromCodePoint(98, 97", "'ba" },
            { ",114)", "'bar'" }
        });

        test_normalization({
            { "String.fromCodePoint(98, 97, 114", "'bar" },
            { ")", "'bar'" }
        });

        test_normalization({
            { "String.fromCodePoint(0x0062", "'b" },
            { ",0x0061, 0x0072)", "'bar'" }
        });

        test_normalization({
            { "String.fromCodePoint(0x00000062, 0x00000061", "'ba" },
            { ", 0x0072)", "'bar'" }
        });

        test_normalization({
            { "String.fromCodePoint(0x00000062, 0x00000061, 0x00000072", "'bar" },
            { ")", "'bar'" }
        });

        test_normalization({
            { "String.fromCodePoint(0x00000062,", "'b" },
            { "0x00000061,", "'ba" },
            { "0x72)",   "'bar'" }
        });

        test_normalization({
            { "String.fromCodePoint(98,", "'b" },
            { "97,", "'ba" },
            { "114)", "'bar'" }
        });
    }
}

TEST_CASE("Mixed input", "[JSNormalizer]")
{
    SECTION("string")
    {
        test_normalization(
            "unescape ( ' A   \\x62   B   \\x61   C   \\x72 ' ) ;",
            "' A   b   B   a   C   r ';"
        );
        test_normalization(
            "unescape ( ' \\x62ar b\\x61r ba\\x72 ' ) ;",
            "' bar bar bar ';"
        );
        test_normalization(
            "unescape ( '\\x62\\x61\\x72', '\\x62\\x61\\x72' ) ;",
            "'bar','bar';"
        );
        test_normalization(
            "unescape ( '\\x62\\x61\\x72' + '\\x62\\x61\\x72' ) ;",
            "'barbar';"
        );
        test_normalization_mixed_encoding(
            "unescape ( '\\x62\\x61\\x72' + '\\u62\\u61\\u72' ) ;",
            "'barbar';"
        );
    }

    SECTION("literal")
    {
        test_normalization(
            "unescape ( 2,  '\\x62\\x61\\x72', 2 ) ;",
            "2,'bar',2;"
        );
    }

    SECTION("identifier")
    {
        test_normalization(
            "unescape ( f(\"A\\u20B\\u20C\"), eval(\"\\u66\\u6f\\u6f\"), \"\\u66\\u6f\\u6f\" ) ;",
            "var_0000(\"A\\u20B\\u20C\"),eval(\"\\u66\\u6f\\u6f\"),\"foo\";"
        );
        test_normalization_mixed_encoding(
            "String.fromCharCode (114, 0x72, eval('123'), 114, 0x72) ;",
            "'rr' eval('123'),114,0x72;"
        );
        test_normalization_mixed_encoding(
            "String.fromCodePoint (114, 0x00000072, eval('123'), 114, 0x00000072) ;",
            "'rr' eval('123'),114,0x00000072;"
        );
    }

    SECTION("comment")
    {
        test_normalization(
            "String.fromCharCode(0x62, \n 0x61, // comment \n 0x72) ;",
            "'bar';"
        );
        test_normalization(
            "String.fromCharCode(0x62, \t 0x61, /* comment */ 0x72) ;",
            "'bar';"
        );
        test_normalization(
            "String.fromCharCode(0x62, \r 0x61, <!-- HTML comment \r 0x72) ;",
            "'bar';"
        );
        test_normalization(
            "String.fromCodePoint(0x00000062, \n 0x00000061, // comment \n 0x00000072) ;",
            "'bar';"
        );
        test_normalization(
            "String.fromCodePoint(0x00000062, \t 0x00000061, /* comment */ 0x00000072) ;",
            "'bar';"
        );
        test_normalization(
            "String.fromCodePoint(0x00000062, \r 0x00000061, <!-- HTML comment \r 0x00000072) ;",
            "'bar';"
        );
    }

    SECTION("nested")
    {
        test_normalization(
            "unescape('\\x62\\x61\\x72'+unescape('\\x62\\x61\\x72')+decodeURI('\\u62\\u61\\u72')) ;",
            "'barbarbar';"
        );
        test_normalization(
            "document.write(unescape('%62%61%72')) ;",
            "document.write('bar');"
        );
        test_normalization(
            "String.fromCodePoint(0x0062, 0x0061, String.fromCharCode(0x0062, 0x0061, 0x0072));",
            "'ba' 'bar';"
        );
        test_normalization(
            "String.fromCharCode(0x0062, 0x0061, String.fromCodePoint(0x0062, 0x0061, 0x0072));",
            "'ba' 'bar';"
        );
    }
}

#endif // CATCH_TEST_BUILD

