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
        test_normalization(
            "'\\x01 \\x23 \\x45 \\x67 \\x89 \\xaA \\xbB \\xcC \\xdD \\xeE \\xfF'",
            "'\u0001 \u0023 \u0045 \u0067 \u0089 \u00aA \u00bB \u00cC \u00dD \u00eE \u00fF'"
        );

    SECTION("\\xXX - unescape function")
        test_normalization(
            "unescape('\\x01 \\x23 \\x45 \\x67 \\x89 \\xaA \\xbB \\xcC \\xdD \\xeE \\xfF')",
            "'\x01 \x23 \x45 \x67 \x89 \xaA \xbB \xcC \xdD \xeE \xfF'"
        );

    SECTION("\\uXXXX")
        test_normalization(
            "'\\u0020 \\u00EB \\u0123 \\u4567 \\u89aA \\ubBcC \\u00dD \\ueEfF'",
            "'\u0020 \u00EB \u0123 \u4567 \u89aA \ubBcC \u00dD \ueEfF'"
        );

    SECTION("\\u{XXXX}")
        test_normalization(
            "'\\u{0020} \\u{00EB} \\u{0123} \\u{4567} \\u{89aA} \\u{bBcC} \\u{00dD} \\u{eEfF}'",
            "'\u0020 \u00EB \u0123 \u4567 \u89aA \ubBcC \u00dD \ueEfF'"
        );

    SECTION("%XX")
        test_normalization(
            "unescape('%01 %23 %45 %67 %89 %aA %bB %cC %dD %eE %fF')",
            "'\x01 \x23 \x45 \x67 \x89 \xaA \xbB \xcC \xdD \xeE \xfF'"
        );

    SECTION("\\uXX")
        test_normalization(
            "unescape('\\u01 \\u23 \\u45 \\u67 \\u89 \\uaA \\ubB \\ucC \\udD \\ueE \\ufF')",
            "'\x01 \x23 \x45 \x67 \x89 \xaA \xbB \xcC \xdD \xeE \xfF'"
        );

    SECTION("%uXXXX")
        test_normalization(
            "unescape('%u0020 %u00EB %u0123 %u4567 %u89aA %ubBcC %u00dD %ueEfF')",
            "'\u0020 \u00EB \u0123 \u4567 \u89aA \ubBcC \u00dD \ueEfF'"
        );

    SECTION("decimal")
    {
        test_normalization(
            "String.fromCharCode(1, 12 ,235, 345, 6789, 1000, 0001)",
            "'\u0001\u000c\u00EB\u0159\u1a85\u03e8\u0001'"
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
            "String.fromCharCode(0x0001, 0X00EB, 0x0123, 0x4567, 0x89aA, 0xbBcC, 0x00dD, 0xeEfF)",
            "'\u0001\u00EB\u0123\u4567\u89aA\ubBcC\u00dD\ueEfF'"
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
            "\\u0065\\u0076\\u0061\\u006C () ; \\u00EB\\u1234 ;",
            "eval();var_0000;"
        );
        test_normalization(
            "'\\u0062\\u0061\\u0072' ; '\\u00EB\\ueEfF' ;",
            "'bar';'\u00EB\ueEfF';"
        );
        test_normalization(
            "\"\\u0062\\u0061\\u0072\" ; \"\\u00EB\\ueEfF\" ;",
            "\"bar\";\"\u00EB\ueEfF\";"
        );
        test_normalization(
            "`\\u0062\\u0061\\u0072` ; `\\u00EB\\ueEfF` ;",
            "`bar`;`\u00EB\ueEfF`;"
        );
        test_normalization(
            "/\\u0062\\u0061\\u0072/ ; /\\u00EB\\ueEfF/ ;",
            "/bar/;/\u00EB\ueEfF/;"
        );
    }

    SECTION("\\xXX")
    {
        test_normalization(
            "'\\x62\\x61\\x72' ; '\\xEB' ;",
            "'bar';'\u00EB';"
        );
        test_normalization(
            "\"\\x62\\x61\\x72\" ; \"\\xEB\" ;",
            "\"bar\";\"\u00EB\";"
        );
        test_normalization(
            "`\\x62\\x61\\x72` ; `\\xEB` ;",
            "`bar`;`\u00EB`;"
        );
        test_normalization(
            "/\\x62\\x61\\x72/ ; /\\xEB/ ;",
            "/bar/;/\u00EB/;"
        );
    }

    SECTION("\\u{XXXX}")
    {
        test_normalization(
            "\\u{0065}\\u{0076}\\u{0061}\\u{006C} () ; \\u{00EB}\\u{1234} ;",
            "eval();var_0000;"
        );
        test_normalization(
            "'\\u{0062}\\u{0061}\\u{0072}'; '\\u{00EB}\\u{eEfF}' ;",
            "'bar';'\u00EB\ueEfF';"
        );
        test_normalization(
            "\"\\u{0062}\\u{0061}\\u{0072}\" ; \"\\u{00EB}\\u{eEfF}\" ;",
            "\"bar\";\"\u00EB\ueEfF\";"
        );
        test_normalization(
            "`\\u{0062}\\u{0061}\\u{0072}` ; `\\u{00EB}\\u{eEfF}` ;",
            "`bar`;`\u00EB\ueEfF`;"
        );
    }
}

TEST_CASE("unescape()", "[JSNormalizer]")
{
    SECTION("%XX")
    {
        test_normalization(
            "unescape('%62%61%72') ; unescape('%EB') ;",
            "'bar';'\xEB';"
        );
        test_normalization(
            "unescape(\"%62%61%72\") ; unescape(\"%EB\") ;",
            "\"bar\";\"\xEB\";"
        );
        test_normalization(
            "unescape(`%62%61%72`) ; unescape(`%EB`) ;",
            "`bar`;`\xEB`;"
        );
    }

    SECTION("%uXXXX")
    {
        test_normalization(
            "unescape('%u0062%u0061%u0072') ; unescape('%u00EB%ueEfF') ;",
            "'bar';'\u00EB\ueEfF';"
        );
        test_normalization(
            "unescape(\"%u0062%u0061%u0072\") ; unescape(\"%u00EB%ueEfF\") ;",
            "\"bar\";\"\u00EB\ueEfF\";"
        );
        test_normalization(
            "unescape(`%u0062%u0061%u0072`) ; unescape(`%u00EB%ueEfF`) ;",
            "`bar`;`\u00EB\ueEfF`;"
        );
    }

    SECTION("\\uXX")
    {
        test_normalization(
            "unescape('\\u62\\u61\\u72') ; unescape('\\uEB') ;",
            "'bar';'\xEB';"
        );
        test_normalization(
            "unescape(\"\\u62\\u61\\u72\") ; unescape(\"\\uEB\") ;",
            "\"bar\";\"\xEB\";"
        );
        test_normalization(
            "unescape(`\\u62\\u61\\u72`) ; unescape(`\\uEB`) ;",
            "`bar`;`\xEB`;"
        );
    }

    SECTION("\\uXXXX")
    {
        test_normalization(
            "unescape('\\u0062\\u0061\\u0072') ; unescape('\\u00EB\\ueEfF') ;",
            "'bar';'\u00EB\ueEfF';"
        );
        test_normalization(
            "unescape(\"\\u0062\\u0061\\u0072\") ; unescape(\"\\u00EB\\ueEfF\") ;",
            "\"bar\";\"\u00EB\ueEfF\";"
        );
        test_normalization(
            "unescape(`\\u0062\\u0061\\u0072`) ; unescape(`\\u00EB\\ueEfF`) ;",
            "`bar`;`\u00EB\ueEfF`;"
        );
    }

    SECTION("\\xXX")
    {
        test_normalization(
            "unescape('\\x62\\x61\\x72') ; unescape('\\xEB') ;",
            "'bar';'\xEB';"
        );
        test_normalization(
            "unescape(\"\\x62\\x61\\x72\") ; unescape(\"\\xEB\") ;",
            "\"bar\";\"\xEB\";"
        );
        test_normalization(
            "unescape(`\\x62\\x61\\x72`) ; unescape(`\\xEB`) ;",
            "`bar`;`\xEB`;"
        );
    }

    SECTION("\\u{XXXX}")
    {
        test_normalization(
            "unescape('\\u{0062}\\u{0061}\\u{0072}') ; unescape('\\u{00EB}\\u{eEfF}') ;",
            "'bar';'\u00EB\ueEfF';"
        );
        test_normalization(
            "unescape(\"\\u{0062}\\u{0061}\\u{0072}\") ; unescape(\"\\u{00EB}\\u{eEfF}\") ;",
            "\"bar\";\"\u00EB\ueEfF\";"
        );
        test_normalization(
            "unescape(`\\u{0062}\\u{0061}\\u{0072}`) ; unescape(`\\u{00EB}\\u{eEfF}`) ;",
            "`bar`;`\u00EB\ueEfF`;"
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
            "decodeURI('%62%61%72') ; decodeURI('%EB') ;",
            "'bar';'\xEB';"
        );
        test_normalization(
            "decodeURI(\"%62%61%72\") ; decodeURI(\"%EB\") ;",
            "\"bar\";\"\xEB\";"
        );
        test_normalization(
            "decodeURI(`%62%61%72`) ; decodeURI(`%EB`) ;",
            "`bar`;`\xEB`;"
        );
    }

    SECTION("%uXXXX")
    {
        test_normalization(
            "decodeURI('%u0062%u0061%u0072') ; decodeURI('%u00EB%ueEfF') ;",
            "'bar';'\u00EB\ueEfF';"
        );
        test_normalization(
            "decodeURI(\"%u0062%u0061%u0072\") ; decodeURI(\"%u00EB%ueEfF\") ;",
            "\"bar\";\"\u00EB\ueEfF\";"
        );
        test_normalization(
            "decodeURI(`%u0062%u0061%u0072`) ; decodeURI(`%u00EB%ueEfF`) ;",
            "`bar`;`\u00EB\ueEfF`;"
        );
    }

    SECTION("\\uXX")
    {
        test_normalization(
            "decodeURI('\\u62\\u61\\u72') ; decodeURI('\\uEB') ;",
            "'bar';'\xEB';"
        );
        test_normalization(
            "decodeURI(\"\\u62\\u61\\u72\") ; decodeURI(\"\\uEB\") ;",
            "\"bar\";\"\xEB\";"
        );
        test_normalization(
            "decodeURI(`\\u62\\u61\\u72`) ; decodeURI(`\\uEB`) ;",
            "`bar`;`\xEB`;"
        );
    }

    SECTION("\\uXXXX")
    {
        test_normalization(
            "decodeURI('\\u0062\\u0061\\u0072') ; decodeURI('\\u00EB\\ueEfF') ;",
            "'bar';'\u00EB\ueEfF';"
        );
        test_normalization(
            "decodeURI(\"\\u0062\\u0061\\u0072\") ; decodeURI(\"\\u00EB\\ueEfF\") ;",
            "\"bar\";\"\u00EB\ueEfF\";"
        );
        test_normalization(
            "decodeURI(`\\u0062\\u0061\\u0072`) ; decodeURI(`\\u00EB\\ueEfF`) ;",
            "`bar`;`\u00EB\ueEfF`;"
        );
    }

    SECTION("\\xXX")
    {
        test_normalization(
            "decodeURI('\\x62\\x61\\x72') ; decodeURI('\\xEB') ;",
            "'bar';'\xEB';"
        );
        test_normalization(
            "decodeURI(\"\\x62\\x61\\x72\") ; decodeURI(\"\\xEB\") ;",
            "\"bar\";\"\xEB\";"
        );
        test_normalization(
            "decodeURI(`\\x62\\x61\\x72`) ; decodeURI(`\\xEB`) ;",
            "`bar`;`\xEB`;"
        );
    }

    SECTION("\\u{XXXX}")
    {
        test_normalization(
            "decodeURI('\\u{0062}\\u{0061}\\u{0072}') ; decodeURI('\\u{00EB}\\u{eEfF}') ;",
            "'bar';'\u00EB\ueEfF';"
        );
        test_normalization(
            "decodeURI(\"\\u{0062}\\u{0061}\\u{0072}\") ; decodeURI(\"\\u{00EB}\\u{eEfF}\") ;",
            "\"bar\";\"\u00EB\ueEfF\";"
        );
        test_normalization(
            "decodeURI(`\\u{0062}\\u{0061}\\u{0072}`) ; decodeURI(`\\u{00EB}\\u{eEfF}`) ;",
            "`bar`;`\u00EB\ueEfF`;"
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
            "decodeURIComponent('%62%61%72') ; decodeURIComponent('%EB') ;",
            "'bar';'\xEB';"
        );
        test_normalization(
            "decodeURIComponent(\"%62%61%72\") ; decodeURIComponent(\"%EB\") ;",
            "\"bar\";\"\xEB\";"
        );
        test_normalization(
            "decodeURIComponent(`%62%61%72`) ; decodeURIComponent(`%EB`) ;",
            "`bar`;`\xEB`;"
        );
    }

    SECTION("%uXXXX")
    {
        test_normalization(
            "decodeURIComponent('%u0062%u0061%u0072') ; decodeURIComponent('%u00EB%ueEfF') ;",
            "'bar';'\u00EB\ueEfF';"
        );
        test_normalization(
            "decodeURIComponent(\"%u0062%u0061%u0072\") ; decodeURIComponent(\"%u00EB%ueEfF\") ;",
            "\"bar\";\"\u00EB\ueEfF\";"
        );
        test_normalization(
            "decodeURIComponent(`%u0062%u0061%u0072`) ; decodeURIComponent(`%u00EB%ueEfF`) ;",
            "`bar`;`\u00EB\ueEfF`;"
        );
    }

    SECTION("\\uXX")
    {
        test_normalization(
            "decodeURIComponent('\\u62\\u61\\u72') ; decodeURIComponent('\\uEB') ;",
            "'bar';'\xEB';"
        );
        test_normalization(
            "decodeURIComponent(\"\\u62\\u61\\u72\") ; decodeURIComponent(\"\\uEB\") ;",
            "\"bar\";\"\xEB\";"
        );
        test_normalization(
            "decodeURIComponent(`\\u62\\u61\\u72`) ; decodeURIComponent(`\\uEB`) ;",
            "`bar`;`\xEB`;"
        );
    }

    SECTION("\\uXXXX")
    {
        test_normalization(
            "decodeURIComponent('\\u0062\\u0061\\u0072') ; decodeURIComponent('\\u00EB\\ueEfF') ;",
            "'bar';'\u00EB\ueEfF';"
        );
        test_normalization(
            "decodeURIComponent(\"\\u0062\\u0061\\u0072\") ; "
                "decodeURIComponent(\"\\u00EB\\ueEfF\") ;",
            "\"bar\";\"\u00EB\ueEfF\";"
        );
        test_normalization(
            "decodeURIComponent(`\\u0062\\u0061\\u0072`) ; decodeURIComponent(`\\u00EB\\ueEfF`) ;",
            "`bar`;`\u00EB\ueEfF`;"
        );
    }

    SECTION("\\xXX")
    {
        test_normalization(
            "decodeURIComponent('\\x62\\x61\\x72') ; decodeURIComponent('\\xEB') ;",
            "'bar';'\xEB';"
        );
        test_normalization(
            "decodeURIComponent(\"\\x62\\x61\\x72\") ; decodeURIComponent(\"\\xEB\") ;",
            "\"bar\";\"\xEB\";"
        );
        test_normalization(
            "decodeURIComponent(`\\x62\\x61\\x72`) ; decodeURIComponent(`\\xEB`) ;",
            "`bar`;`\xEB`;"
        );
    }

    SECTION("\\u{XXXX}")
    {
        test_normalization(
            "decodeURIComponent('\\u{0062}\\u{0061}\\u{0072}') ; "
                "decodeURIComponent('\\u{00EB}\\u{eEfF}') ;",
            "'bar';'\u00EB\ueEfF';"
        );
        test_normalization(
            "decodeURIComponent(\"\\u{0062}\\u{0061}\\u{0072}\") ; "
                "decodeURIComponent(\"\\u{00EB}\\u{eEfF}\") ;",
            "\"bar\";\"\u00EB\ueEfF\";"
        );
        test_normalization(
            "decodeURIComponent(`\\u{0062}\\u{0061}\\u{0072}`) ; "
                "decodeURIComponent(`\\u{00EB}\\u{eEfF}`) ;",
            "`bar`;`\u00EB\ueEfF`;"
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

TEST_CASE("Internal limits", "[JSNormalizer]")
{
    SECTION("output tail size")
    {
        test_normalization(
            "function v(e){return new String(/^(?:(?:(?:https?|ftp):)?\\/\\/)(?"
            ":\\S+(?::\\S*)?@)?(?:(?!(?:10|127)(?:\\.\\d{1,3}){3})(?!(?:169\\.2"
            "54|192\\.168)(?:\\.\\d{1,3}){2})(?!172\\.(?:1[6-9]|2\\d|3[0-1])(?:"
            "\\.\\d{1,3}){2})(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])(?:\\.(?:1?"
            "\\d{1,2}|2[0-4]\\d|25[0-5])){2}(?:\\.(?:[1-9]\\d?|1\\d\\d|2[0-4]\\"
            "d|25[0-4]))|(?:(?:[a-z 0-9\\u0061-\\u007a][a-z 0-9\\u0061-\\u007a_"
            "-]{0,62})?[a-z 0-9\\u0061-\\u007a]\\.)+(?:[a-z \\u0061-\\u007a]{2,"
            "}\\.?))(?::\\d{2,5})?(?:[/?#]\\S*)?$/i).test(e)}",
            "function var_0000(var_0001){return new String(/^(?:(?:(?:https?|ft"
            "p):)?\\/\\/)(?:\\S+(?::\\S*)?@)?(?:(?!(?:10|127)(?:\\.\\d{1,3}){3}"
            ")(?!(?:169\\.254|192\\.168)(?:\\.\\d{1,3}){2})(?!172\\.(?:1[6-9]|2"
            "\\d|3[0-1])(?:\\.\\d{1,3}){2})(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3"
            "])(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}(?:\\.(?:[1-9]\\d?|1\\"
            "d\\d|2[0-4]\\d|25[0-4]))|(?:(?:[a-z 0-9a-z][a-z 0-9a-z_-]{0,62})?["
            "a-z 0-9a-z]\\.)+(?:[a-z a-z]{2,}\\.?))(?::\\d{2,5})?(?:[/?#]\\S*)?"
            "$/i).test(var_0001)}"
        );
    }
}

#endif // CATCH_TEST_BUILD

