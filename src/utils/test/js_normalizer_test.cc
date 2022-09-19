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
// js_normalizer_test.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>

#include "catch/catch.hpp"

#include "utils/js_identifier_ctx.h"
#include "utils/js_normalizer.h"

#include "js_test_utils.h"

using namespace snort;
using namespace std::string_literals;

#ifdef CATCH_TEST_BUILD

// ClamAV test vectors from: https://github.com/Cisco-Talos/clamav/blob/main/unit_tests/check_jsnorm.c

TEST_CASE("clamav tests", "[JSNormalizer]")
{
    SECTION("test_case_0 - mixed identifiers and comments")
    {
        test_normalization_noident(
        "function foo(a, b) {\n"
        "var x = 1.9e2*2*a/ 4.;\n"
        "var y = 'test\\'tst';//var\n"
        "x=b[5],/* multiline\nvar z=6;\nsome*some/other**/"
        "z=x/y;/* multiline oneline */var t=z/a;\n"
        "z=[test,testi];"
        "document.writeln('something\\n');}",

        "function foo(a,b){var x=1.9e2*2*a/4.;var y='test\\'tst';x=b[5],z=x/y;var t=z/a;"
        "z=[test,testi];document.writeln('something\\n');}"
        );
    }
    SECTION("test_case_1 - escaped unicode in identifier")
    {
        test_normalization_noident(
            "function () { var id\\u1234tx;}",
            "function(){var id\u1234tx;}"
        );
    }
    SECTION("test_case_2 - accumulated string assignment")
    {
        test_normalization_noident(
            "function () { var tst=\"a\"+'bc'+     'd'; }",
            "function(){var tst=\"abcd';}"
        );
    }
    SECTION("test_case_3 - percent-encoded string")
    {
        test_normalization_noident(
            "dF('bmfsu%2639%2638x11u%2638%263%3A%264C1');",
            "dF('bmfsu%2639%2638x11u%2638%263%3A%264C1');"
        );
    }
    SECTION("test_case_4 - percent-encoded string")
    {
        test_normalization_noident(
            "qbphzrag.jevgr(harfpncr('%3P%73%63%72%69%70%74%20%6P%61%6R%67%75%61%67%65%3Q%22%6N%61%76%61"
                "%73%63%72%69%70%74%22%3R%66%75%6R%63%74%69%6S%6R%20%64%46%28%73%29%7O%76%61%72%20%73%31"
                "%3Q%75%6R%65%73%63%61%70%65%28%73%2R%73%75%62%73%74%72%28%30%2P%73%2R%6P%65%6R%67%74%68"
                "%2Q%31%29%29%3O%20%76%61%72%20%74%3Q%27%27%3O%66%6S%72%28%69%3Q%30%3O%69%3P%73%31%2R%6P"
                "%65%6R%67%74%68%3O%69%2O%2O%29%74%2O%3Q%53%74%72%69%6R%67%2R%66%72%6S%6Q%43%68%61%72%43"
                "%6S%64%65%28%73%31%2R%63%68%61%72%43%6S%64%65%41%74%28%69%29%2Q%73%2R%73%75%62%73%74%72"
                "%28%73%2R%6P%65%6R%67%74%68%2Q%31%2P%31%29%29%3O%64%6S%63%75%6Q%65%6R%74%2R%77%72%69%74"
                "%65%28%75%6R%65%73%63%61%70%65%28%74%29%29%3O%7Q%3P%2S%73%63%72%69%70%74%3R'));"
                "riny(qS('tV%285%3O%285%3Nsdwjl%28585%3N7%28586Q%28585%3N7%3P%7P55l%28585%3N7%3P%28585%3N7"
                "%28586R%28585%3N8T5%285%3N%285%3P%286R3'));",

            "qbphzrag.jevgr(harfpncr('%3P%73%63%72%69%70%74%20%6P%61%6R%67%75%61%67%65%3Q%22%6N%61%76%61"
                "%73%63%72%69%70%74%22%3R%66%75%6R%63%74%69%6S%6R%20%64%46%28%73%29%7O%76%61%72%20%73%31"
                "%3Q%75%6R%65%73%63%61%70%65%28%73%2R%73%75%62%73%74%72%28%30%2P%73%2R%6P%65%6R%67%74%68"
                "%2Q%31%29%29%3O%20%76%61%72%20%74%3Q%27%27%3O%66%6S%72%28%69%3Q%30%3O%69%3P%73%31%2R%6P"
                "%65%6R%67%74%68%3O%69%2O%2O%29%74%2O%3Q%53%74%72%69%6R%67%2R%66%72%6S%6Q%43%68%61%72%43"
                "%6S%64%65%28%73%31%2R%63%68%61%72%43%6S%64%65%41%74%28%69%29%2Q%73%2R%73%75%62%73%74%72"
                "%28%73%2R%6P%65%6R%67%74%68%2Q%31%2P%31%29%29%3O%64%6S%63%75%6Q%65%6R%74%2R%77%72%69%74"
                "%65%28%75%6R%65%73%63%61%70%65%28%74%29%29%3O%7Q%3P%2S%73%63%72%69%70%74%3R'));"
                "riny(qS('tV%285%3O%285%3Nsdwjl%28585%3N7%28586Q%28585%3N7%3P%7P55l%28585%3N7%3P%28585%3N7"
                "%28586R%28585%3N8T5%285%3N%285%3P%286R3'));"
        );
    }
    SECTION("test_case_5 - obfuscated script")
    {
        test_normalization_noident(
            "shapgvba (c,n,p,x,r,e){}('0(\\'1\\');',2,2,'nyreg|j00g'.fcyvg('|'),0,{});",
            "shapgvba(c,n,p,x,r,e){}('0(\\'1\\');',2,2,'nyreg|j00g'.fcyvg('|'),0,{});"
        );
    }
    SECTION("test_case_6 - obfuscated script")
    {
        test_normalization_noident(
            "function $(p,a,c,k,e,d){} something(); $('0(\\'1\\');',2,2,'alert|w00t'.split('|'),0,{});",
            "function $(p,a,c,k,e,d){}something();$('0(\\'1\\');',2,2,'alert|w00t'.split('|'),0,{});"
        );
    }

#define B64 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    SECTION("test_case_7 - single quotes string")
    {
        test_normalization_noident(
            "var z=\"tst" B64 "tst\";",
            "var z=\"tst" B64 "tst\";"
        );
    }
    SECTION("test_case_8 - double quotes string")
    {
        test_normalization_noident(
            "var z=\'tst" B64 "tst\';",
            "var z=\'tst" B64 "tst\';"
        );
    }
    SECTION("test_case_9 - obfuscated script")
    {
        test_normalization_noident(
            "riny(harfpncr('%61%6p%65%72%74%28%27%74%65%73%74%27%29%3o'));",
            "riny(harfpncr('%61%6p%65%72%74%28%27%74%65%73%74%27%29%3o'));"
        );
    }
    SECTION("test_case_10 - obfuscated script")
    {
        test_normalization_noident(
            "function $ $() dF(x); function (p,a,c,k,e,r){function $(){}",
            "function $ $()dF(x);function(p,a,c,k,e,r){function $(){}"
        );
    }
    SECTION("test_case_11 - integer literal")
    {
        test_normalization_noident(
            "var x=123456789 ;",
            "var x=123456789;"
        );
    }
    SECTION("test_case_12 - escaped unicode in string literal")
    {
        test_normalization_noident(
            "var x='test\\u0000test';"s,
            "var x='test\u0000test';"s
        );
    }
    // FIXIT-L this should be revisited
    SECTION("test_case_13 - invalid escape sequence")
    {
        test_normalization_noident(
            "var x\\s12345",
            "var x\\s12345"
        );
    }
    SECTION("test_case_14 - EOF in the middle of string literal")
    {
        test_normalization_noident(
            "document.write(unescape('test%20test",
            "document.write('test test"
        );
    }
}

// Test vectors for all match patterns
static const char all_patterns_buf0[] =
    "var  \x9\xB\xC\x20\xA0\x8\xA\xD\xEF\xBB\xBF\xE2\x80\xA8\xE2\x80\xA9\n"
    "  \n\t\r\v  a; \0";

static const char all_patterns_expected0[] =
    "var a;";

static const char all_patterns_buf1[] =
    "<!-- var html_comment = 'comment' ;\n"
    "var a = 1;// first var\nvar b = 2;  /* second var\nvar foo = 'bar'\n*/"
    "\nvar c = 3; // third var";

static const char all_patterns_expected1[] =
    "var a=1;var b=2;var c=3;";

static const char all_patterns_buf2[] =
    "{ a } ( a ) [ a ] a >= b a == b a != b a === b a !== b a /= b . ; , "
    "a < b a > b a <= b a + b- c a * b a % b a ++; --b a << 2 a >> 3 a >>> 4 a & b a | b "
    "a ^ b ! a a && b a || b ?: a = 2 a += 2 a -= 2 a *= 2 a %= 2 a <<= b a >>= b a >>>= b "
    "a &= b a|= b a ^= b a/b ~ a";

static const char all_patterns_expected2[] =
    "{a}(a)[a]a>=b a==b a!=b a===b a!==b a/=b.;,a<b a>b a<=b a+b-c a*b "
    "a%b a++;--b a<<2 a>>3 a>>>4 a&b a|b a^b!a a&&b a||b?:a=2 a+=2 a-=2 a*=2 a%=2 a<<=b "
    "a>>=b a>>>=b a&=b a|=b a^=b a/b~a";

static const char all_patterns_buf3[] =
    "break case debugger in import protected do else function try "
    "implements static instanceof new this class let a typeof var a with enum private catch "
    "continue default extends public finally for if super yield return switch throw const a "
    "interface void while delete export package";

static const char all_patterns_expected3[] =
    "break case debugger in import protected do else function try "
    "implements static instanceof new this class let a typeof var a with enum private catch "
    "continue default extends public finally for if super yield return switch throw const a "
    "interface void while delete export package";

static const char all_patterns_buf4[] =
    "/regex/g undefined null true false 2 23 2_3 2.3 2.23 2.2_3 .2 .02 .0_2 4. +2 -2 "
    "+3.3 -3.3 +23 -32 2.3E45 2.3E4_5 3.E34 -2.3E45 -3.E34 +2.3E45 +3.E34 0b101 0B111 0o357 0O777 "
    "0373 0x1234 0XFFFF 123n 0b101n 0o123n 0xaffn Infinity \xE2\x88\x9E NaN \"\" \"double string\" "
    "\"d\" '' 'single string' 's' x=/regex/gs x=2/2/1 `\ntemplate\n`";

static const char all_patterns_expected4[] =
    "/regex/g undefined null true false 2 23 2_3 2.3 2.23 2.2_3 .2 .02 .0_2 4.+2-2"
    "+3.3-3.3+23-32 2.3E45 2.3E4_5 3.E34-2.3E45-3.E34+2.3E45+3.E34 0b101 0B111 0o357 0O777 0373 "
    "0x1234 0XFFFF 123n 0b101n 0o123n 0xaffn Infinity \xE2\x88\x9E NaN \"\" \"double string\" "
    "\"d\" '' 'single string' 's' x=/regex/gs x=2/2/1 `\ntemplate\n`";

static const char all_patterns_buf5[] =
    "$2abc _2abc abc $__$ 肖晗 XÆA12 \\u0041abc \\u00FBdef \\u1234ghi ab\xE2\x80\xA8ww "
    "ab\xE2\x80\xA9ww ab\xEF\xBB\xBFww ab∞ww 2abc _a _1;"
    "var a;var _1;";

static const char all_patterns_expected5[] =
    "$2abc _2abc abc $__$ 肖晗 XÆA12 \u0041abc \u00FBdef \u1234ghi ab;ww "
    "ab;ww ab ww ab ∞ ww 2 abc _a _1;"
    "var a;var _1;";

static const char all_patterns_buf6[] =
    "tag` template\n   ${ a   +   b }   template`";

static const char all_patterns_expected6[] =
    "tag ` template\n   ${a+b}   template`";

static const char all_patterns_buf7[] =
    "/Day:   \\d{2}\\/Month:   \\d{2}\\/Year:   \\d{4}/;"
    "/<\\d{3}>\\//g";

static const char all_patterns_expected7[] =
    "/Day:   \\d{2}\\/Month:   \\d{2}\\/Year:   \\d{4}/;"
    "/<\\d{3}>\\//g";

static const char all_patterns_buf8[] =
    "a = \"   \\\"   \\\\\\\"   \\\\\";"
    "b = `   \\`   \\\\\\`   \\\\`;"
    "c = '   \\'   \\\\\\'   \\\\';"
    "d = /   \\/   \\\\\\/   \\\\/;"
    "a + b;";

static const char all_patterns_expected8[] =
    "a=\"   \\\"   \\\\\\\"   \\\\\";"
    "b=`   \\`   \\\\\\`   \\\\`;"
    "c='   \\'   \\\\\\'   \\\\';"
    "d=/   \\/   \\\\\\/   \\\\/;"
    "a+b;";

static const char all_patterns_buf9[] =
    "var r = /^(?:(?:https?|mailto|ftp):|[^:/?#]*(?:[/?#]|$))/i;"
    "new Lb(function(a){return /^[^:]*([/?#]|$)/.test(a)});"
    "pa=/^((https:)?\\/\\/[0-9a-z.:[\\]-]+\\/|\\/[^/\\\\]|"
    "[^:/\\\\%]+\\/|[^:/\\\\%]*[?#]|about:blank#)/i;"
    "/[/ a  b   c / 1]/ a  b   c / 1;";

static const char all_patterns_expected9[] =
    "var r=/^(?:(?:https?|mailto|ftp):|[^:/?#]*(?:[/?#]|$))/i;"
    "new Lb(function(a){return /^[^:]*([/?#]|$)/.test(a)});"
    "pa=/^((https:)?\\/\\/[0-9a-z.:[\\]-]+\\/|\\/[^/\\\\]"
    "|[^:/\\\\%]+\\/|[^:/\\\\%]*[?#]|about:blank#)/i;"
    "/[/ a  b   c / 1]/ a b c/1;";

static const char all_patterns_buf10[] =
    "function(a){if(!/^\\s*{/.test(a))return!1;a=_.xf(a);return null!==a&&\"object\"===typeof a&&!!a.g};"
    "/^\\s*$/.test(Q)?0:/^[\\],:{}]*$/.replace(/(?=:|,|]|}|$)/g,z)";

static const char all_patterns_expected10[] =
    "function(a){if(!/^\\s*{/.test(a))return!1;a=_.xf(a);return null!==a&&\"object\"===typeof a&&!!a.g};"
    "/^\\s*$/.test(Q)?0:/^[\\],:{}]*$/.replace(/(?=:|,|]|}|$)/g,z)";

TEST_CASE("all patterns", "[JSNormalizer]")
{
    SECTION("whitespaces and special characters")
    {
        test_normalization_noident(
            all_patterns_buf0,
            all_patterns_expected0
        );
    }
    SECTION("comments")
    {
        test_normalization_noident(
            all_patterns_buf1,
            all_patterns_expected1
        );
    }
    SECTION("directives")
    {
        const char src0[] = "'use strict'\nvar a = 1;";
        const char src1[] = "\"use strict\"\nvar a = 1;";
        const char src2[] = "'use strict';var a = 1;";
        const char src3[] = "\"use strict\";var a = 1;";
        const char src4[] = "var a = 1 'use strict';";

        const char expected0[] = "'use strict';var a=1;";
        const char expected1[] = "\"use strict\";var a=1;";
        const char expected2[] = "var a=1 'use strict';";

        test_normalization_noident(src0, expected0);
        test_normalization_noident(src1, expected1);
        test_normalization_noident(src2, expected0);
        test_normalization_noident(src3, expected1);
        test_normalization_noident(src4, expected2);
    }
    SECTION("punctuators")
    {
        test_normalization_noident(
            all_patterns_buf2,
            all_patterns_expected2
        );
    }
    SECTION("keywords")
    {
        test_normalization_noident(
            all_patterns_buf3,
            all_patterns_expected3
        );
    }
    SECTION("literals")
    {
        test_normalization_noident(
            all_patterns_buf4,
            all_patterns_expected4
        );
    }
    SECTION("identifiers")
    {
        test_normalization_noident(
            all_patterns_buf5,
            all_patterns_expected5
        );
    }
    SECTION("template literals")
    {
        test_normalization_noident(
            all_patterns_buf6,
            all_patterns_expected6
        );
    }
    SECTION("regex literal with slashes")
    {
        test_normalization_noident(
            all_patterns_buf7,
            all_patterns_expected7
        );
    }
    SECTION("multiple escaped slashes")
    {
        test_normalization_noident(
            all_patterns_buf8,
            all_patterns_expected8
        );
    }
    SECTION("slashes and braces")
    {
        test_normalization_noident(
            all_patterns_buf9,
            all_patterns_expected9
        );
    }
    SECTION("regex literal with curly brace")
    {
        test_normalization_noident(
            all_patterns_buf10,
            all_patterns_expected10
        );
    }
}

// Test vectors for different syntax cases
static const char syntax_cases_buf0[] =
    "var a;\n"
    "var b = \"init this    stuff\";\n"
    "var c = \"Hi\" + \" \" + \"Joe\";\n"
    "var d = 1 + 2 + \"3\";\n"
    "var e = [ 2, 3, 5, 8 ];\n"
    "var f = false;\n"
    "var g = /( i'm   a  .* regex )/;\n"
    "var h = function(){};\n"
    "const PI = 3.14;\n"
    "var a = 1, b = 2, c = a + b;\n"
    "let z = 'zzz zz';\n"
    "var g = null;\n"
    "var name = { first: \"Jane\", last: \"Doe\" };\n"
    "var esc = 'I don\\'t \\n know';\n";

static const char syntax_cases_expected0[] =
    "var a;var b=\"init this    stuff\";var c=\"Hi Joe\";"
    "var d=1+2+\"3\";var e=[2,3,5,8];var f=false;var g=/( i'm   a  .* regex )/;"
    "var h=function(){};const PI=3.14;var a=1,b=2,c=a+b;let z='zzz zz';var g=null;"
    "var name={first:\"Jane\",last:\"Doe\"};var esc='I don\\'t \\n know';";

static const char syntax_cases_buf1[] =
    "a = b + c - d;\n"
    "a = b * (c / d);\n"
    "x = 100 % 48;\n"
    "a ++; b -- ; -- a; ++    b;\n";

static const char syntax_cases_expected1[] =
    "a=b+c-d;a=b*(c/d);x=100%48;a++;b--;--a;++b;";

static const char syntax_cases_buf2[] =
    "!(a == b);\n"
    "a != b;\n"
    "typeof a;\n"
    "x << 2; x >> 3;\n"
    "a = b;\n"
    "a == b;\n"
    "a != b;\n"
    "a === b;\n"
    "a !== b;\n"
    "a < b; a > b;\n"
    "a <= b;  a >= b;\n"
    "a += b;\n"
    "a && b;\n"
    "a || b;\n";

static const char syntax_cases_expected2[] =
    "!(a==b);a!=b;typeof a;x<<2;x>>3;a=b;a==b;a!=b;a===b;a!==b;a<b;a>b;"
    "a<=b;a>=b;a+=b;a&&b;a||b;";

static const char syntax_cases_buf3[] =
    "var foo = {\n"
        "firstFoo: \"FooFirst\",\n"
        "secondFoo: \"FooSecond\",\n"
        "thirdFoo: 10,\n"
        "fourthFoo: 120,\n"
        "methodFoo : function () {\n"
            "\treturn this.firstFoo + \" \" + this.secondFoo;\n"
        "}\n"
    "};\n";

static const char syntax_cases_expected3[] =
    "var foo={firstFoo:\"FooFirst\",secondFoo:\"FooSecond\","
    "thirdFoo:10,fourthFoo:120,methodFoo:function(){return this.firstFoo+\" \"+"
    "this.secondFoo;}};";

static const char syntax_cases_buf4[] =
    "var dogs = [\"Bulldog\", \"Beagle\", \"Labrador\"];\n"
    "var dogs = new Array(\"Bulldog\", \"Beagle\", \"Labrador\");\n"
    "\t\t\t\n"
    "alert( dogs[ 1 ] );\n"
    "dogs[0] = \"Bull Terrier\";\n"
    "\n"
    "for (var i = 0; i < dogs.length; i++) {\n"
        "console.log(dogs[i]);\n"
    "}\n\r";

static const char syntax_cases_expected4[] =
    "var dogs=[\"Bulldog\",\"Beagle\",\"Labrador\"];"
    "var dogs=new Array(\"Bulldog\",\"Beagle\",\"Labrador\");alert(dogs[1]);"
    "dogs[0]=\"Bull Terrier\";for(var i=0;i<dogs.length;i++){console.log(dogs[i]);}";

static const char syntax_cases_buf5[] =
    "var i = 1;\n"
    "while (i < 100) {\n"
        "i *= 2;\n"
        "document.write(i + \", \");\n"
    "}\n"
    "\n"
    "i = 1;\n"
    "do {\n"
        "i *= 2;\n"
        "document.write(i + \", \");\n"
    "} while (i < 100)\n"
    "\n"
    "for (var i = 0; i < 10; i++) {\n"
        "if (i == 5) { break; }\n"
        "document.write(i + \", \");\n"
    "}\n"
    "\n"
    "for (var i = 0; i < 10; i++) {\n"
        "if (i == 5) { continue; }\n"
        "document.write(i + \", \");\n"
    "}\n\r";

static const char syntax_cases_expected5[] =
    "var i=1;while(i<100){i*=2;document.write(i+\", \");}i=1;do{i*=2;"
    "document.write(i+\", \");}while(i<100);for(var i=0;i<10;i++){if(i==5){break;}"
    "document.write(i+\", \");}for(var i=0;i<10;i++){if(i==5){continue;}"
    "document.write(i+\", \");}";

static const char syntax_cases_buf6[] =
    "var n = 1800;\n"
    "var res;\n"
    "if ( (n >= 1400) && (n < 1900) ) {\n"
        "res = \"In range.\";\n"
    "} else {\n"
        "res = \"Not in range.\";\n"
    "}\n"
    "\n"
    "var text;\n"
    "switch ( new Date().getDay() ) {\n"
        "case 6:\n"
            "text = \"Saturday\";\n"
            "break;\n"
        "case 0:\n"
            "text = \"Sunday\";\n"
            "break;\n"
        "default:\n"
            "text = \"Whatever\";\n"
    "}\n\r";

static const char syntax_cases_expected6[] =
    "var n=1800;var res;if((n>=1400)&&(n<1900)){res=\"In range.\";}"
    "else{res=\"Not in range.\";}var text;switch(new Date().getDay()){case 6:"
    "text=\"Saturday\";break;case 0:text=\"Sunday\";break;default:text=\"Whatever\";}";

static const char syntax_cases_buf7[] =
    "var x = document.getElementById(\"mynum\").value;\n"
    "try { \n"
        "if(x == \"\")  throw \"empty\";\n"
        "if(isNaN(x)) throw \"not a number\";\n"
        "x = Number(x);\n"
        "if(x > 10)   throw \"too high\";\n"
    "}\n"
    "catch(err) {\n"
        "document.write(\"Input is \" + err);\n"
        "console.error(err);\n"
    "}\n"
    "finally {\n"
        "document.write(\"</br />Done\");\n"
    "}\n\r";

static const char syntax_cases_expected7[] =
    "var x=document.getElementById(\"mynum\").value;try{if(x==\"\")"
    "throw \"empty\";if(isNaN(x))throw \"not a number\";x=Number(x);if(x>10)"
    "throw \"too high\";}catch(err){document.write(\"Input is \"+err);console.error(err);}"
    "finally{document.write(\"</br />Done\");}";

static const char syntax_cases_buf8[] =
    "function sum (a, b) {\n"
    "return new Promise(function (resolve, reject) {\n"
        "setTimeout(function () {\n"
        "if (typeof a !== \"number\" || typeof b !== \"number\") {\n"
            "return reject(new TypeError(\"Inputs must be numbers\"));\n"
        "}\n"
        "resolve(a + b);\n"
        "}, 1000);\n"
    "});\n"
    "}\n"
    "\n"
    "var myPromise = sum(10, 5);\n"
    "myPromise.then(function (result) {\n"
        "document.write(\" 10 + 5: \", result);\n"
        "return sum(null, \"foo\");\n"
        "}).then(function () {\n"
        "}).catch(function (err) {\n"
        "console.error(err);\n"
    "});\n\r";

static const char syntax_cases_expected8[] =
    "function sum(a,b){return new Promise(function(resolve,reject)"
    "{setTimeout(function(){if(typeof a!==\"number\"||typeof b!==\"number\"){return "
    "reject(new TypeError(\"Inputs must be numbers\"));}resolve(a+b);},1000);});}"
    "var myPromise=sum(10,5);myPromise.then(function(result){"
    "document.write(\" 10 + 5: \",result);return sum(null,\"foo\");}).then(function(){})"
    ".catch(function(err){console.error(err);});";

static const char syntax_cases_buf9[] =
    "var a = Math.round( (new Date).getTime()/1E3 );\n"
    "var b = a.match( /^[0-9a-z-_.]{10,1200}$/i );\n"
    "var c = a.match( /=\\s*{((.|\\s)*?)};/g ) ;\n\r";

static const char syntax_cases_expected9[] =
    "var a=Math.round((new Date).getTime()/1E3);"
    "var b=a.match(/^[0-9a-z-_.]{10,1200}$/i);"
    "var c=a.match(/=\\s*{((.|\\s)*?)};/g);";

static const char syntax_cases_buf10[] =
    "var a = 2\n/ab -cd/";

static const char syntax_cases_expected10[] =
    "var a=2;/ab -cd/";

static const char syntax_cases_buf11[] =
    "var d_str1 = \"\\\\ \" ; var d_str2 = \"abc\\\"def\" ;"
    "var d_str3 = \"\\\"abc \" ;var s_str1 = '\\\\ ' ; var s_str2 = 'abc\\\'def' ; "
    "var s_str3 = '\\\'abc ' ;var re_1 = /\\\\ / ; var re_2 = /abc\\/def/ ; "
    "var re_3 = /\\/abc / ;";

static const char syntax_cases_expected11[] =
    "var d_str1=\"\\\\ \";var d_str2=\"abc\\\"def\";"
    "var d_str3=\"\\\"abc \";var s_str1='\\\\ ';var s_str2='abc\\\'def';"
    "var s_str3='\\\'abc ';var re_1=/\\\\ /;var re_2=/abc\\/def/;var re_3=/\\/abc /;";

static const char syntax_cases_buf12[] =
    "var str1 = \"abc\\\n def\" ;"
    "var str2 = \"abc\\\r\n def\" ;"
    "var str3 = 'abc\\\n def' ;"
    "var str4 = 'abc\\\r\n def' ;";

static const char syntax_cases_expected12[] =
    "var str1=\"abc def\";"
    "var str2=\"abc def\";"
    "var str3='abc def';"
    "var str4='abc def';";

static const char syntax_cases_buf13[] =
    "return /regex/i.test( str ) ;";

static const char syntax_cases_expected13[] =
    "return /regex/i.test(str);";

static const char syntax_cases_buf14[] =
    "var a = b+ ++c ;\n"
    "var a = b++ +c ;\n"
    "var a = b++ + ++c ;\n"
    "var a = b- --c ;\n"
    "var a = b-- -c ;\n"
    "var a = b-- - --c ;\n"
    "var a = b++ - ++c ;\n"
    "var a = b * -c ;\n"
    "var a = b % -c ;\n"
    "var a = b + -c ;";

static const char syntax_cases_expected14[] =
    "var a=b+ ++c;"
    "var a=b++ +c;"
    "var a=b++ + ++c;"
    "var a=b- --c;"
    "var a=b-- -c;"
    "var a=b-- - --c;"
    "var a=b++ - ++c;"
    "var a=b* -c;"
    "var a=b% -c;"
    "var a=b+ -c;";

// In the following cases:
//   a reading cursor will be after the literal
//   a malformed literal is not present in the output

static const char syntax_cases_buf15[] =
    "var invalid_str = 'abc\u2028 def' ;\n";

static const char syntax_cases_expected15[] =
    "var invalid_str='abc\u2028 def';";

static const char syntax_cases_buf16[] =
    "var invalid_str = \"abc\n def\"";

static const char syntax_cases_expected16[] =
    "var invalid_str=\"abc";

static const char syntax_cases_buf17[] =
    "var invalid_str = 'abc\r def'";

static const char syntax_cases_expected17[] =
    "var invalid_str='abc";

static const char syntax_cases_buf18[] =
    "var invalid_str = 'abc\\\n\r def'";

static const char syntax_cases_expected18[] =
    "var invalid_str='abc";

static const char syntax_cases_buf19[] =
    "var invalid_re = /abc\\\n def/";

static const char syntax_cases_expected19[] =
    "var invalid_re=/abc";

static const char syntax_cases_buf20[] =
    "var invalid_re = /abc\\\r\n def/";

static const char syntax_cases_expected20[] =
    "var invalid_re=/abc";

static const char syntax_cases_buf21[] =
    "var invalid_str = 'abc\u2029 def' ;\n\r";

static const char syntax_cases_expected21[] =
    "var invalid_str='abc\u2029 def';";

static const char syntax_cases_buf22[] =
    "tag`template\n \\\\\\${   }   \\\\${   a  + ` template ${ 1 + c  }`  }`";

static const char syntax_cases_expected22[] =
    "tag `template\n \\\\\\${   }   \\\\${a+` template ${1+c}`}`";

static const char syntax_cases_buf23[] =
    "`${`${`${`${`${}`}`}`}`}`}";

static const char syntax_cases_expected23[] =
    "`${`${`${`${`";

static const char syntax_cases_buf24[] =
    "var a=/((((/))))/;"
    "var b=/(((((/)))))/;";

static const char syntax_cases_expected24[] =
    "var a=/((((/))))/;"
    "var b=/((((";

static const char syntax_cases_buf25[] =
    "return /regex0/.foo + /regex1/.bar ;"
    "return /regex2/.baz * /regex3/.qux ;";

static const char syntax_cases_expected25[] =
    "return /regex0/.var_0000+/regex1/.var_0001;"
    "return /regex2/.var_0002*/regex3/.var_0003;";

static const char syntax_cases_buf26[] =
    "var invalid_re = /abc \n def/ ;";

static const char syntax_cases_expected26[] =
    "var invalid_re=/abc ";

TEST_CASE("syntax cases", "[JSNormalizer]")
{
    SECTION("variables")
    {
        test_normalization_noident(
            syntax_cases_buf0,
            syntax_cases_expected0
        );
    }
    SECTION("operators")
    {
        test_normalization_noident(
            syntax_cases_buf1,
            syntax_cases_expected1
        );
    }
    SECTION("arithmetic and logical operators")
    {
        test_normalization_noident(
            syntax_cases_buf2,
            syntax_cases_expected2
        );
    }
    SECTION("complex object")
    {
        test_normalization_noident(
            syntax_cases_buf3,
            syntax_cases_expected3
        );
    }
    SECTION("arrays")
    {
        test_normalization_noident(
            syntax_cases_buf4,
            syntax_cases_expected4
        );
    }
    SECTION("loops")
    {
        test_normalization_noident(
            syntax_cases_buf5,
            syntax_cases_expected5
        );
    }
    SECTION("if-else and switch statements")
    {
        test_normalization_noident(
            syntax_cases_buf6,
            syntax_cases_expected6
        );
    }
    SECTION("try-catch statements")
    {
        test_normalization_noident(
            syntax_cases_buf7,
            syntax_cases_expected7
        );
    }
    SECTION("functions and promises")
    {
        test_normalization_noident(
            syntax_cases_buf8,
            syntax_cases_expected8
        );
    }
    SECTION("regex-division ambiguity")
    {
        test_normalization_noident(
            syntax_cases_buf9,
            syntax_cases_expected9
        );
    }
    SECTION("regex on a new line")
    {
        test_normalization_noident(
            syntax_cases_buf10,
            syntax_cases_expected10
        );
    }
    SECTION("string and regex literals ambiguity with escaped sentinel chars")
    {
        test_normalization_noident(
            syntax_cases_buf11,
            syntax_cases_expected11
        );
    }
    SECTION("escaped LF and CR chars in literals")
    {
        test_normalization_noident(
            syntax_cases_buf12,
            syntax_cases_expected12
        );
    }
    SECTION("regex after keyword")
    {
        test_normalization_noident(
            syntax_cases_buf13,
            syntax_cases_expected13
        );
    }
    SECTION("white space between '+'<-->'++' and '-'<-->'--'")
    {
        test_normalization_noident(
            syntax_cases_buf14,
            syntax_cases_expected14
        );
    }
    SECTION("LS within literal")
    {
        test_normalization_noident(syntax_cases_buf15, syntax_cases_expected15);
    }
    SECTION("PS within literal")
    {
        test_normalization_noident(syntax_cases_buf21, syntax_cases_expected21);
    }
    SECTION("template literals")
    {
        test_normalization_noident(
            syntax_cases_buf22,
            syntax_cases_expected22
        );
    }
    SECTION("regex after operator")
    {
        test_normalization(syntax_cases_buf25, syntax_cases_expected25);
    }
}

TEST_CASE("bad tokens", "[JSNormalizer]")
{
    SECTION("explicit LF within literal")
        test_normalization_noident(
            syntax_cases_buf16, syntax_cases_expected16,
            {
                return_code(JSTokenizer::BAD_TOKEN),
                expected_cursor_pos(23)
            });

    SECTION("explicit CR within literal")
        test_normalization_noident(
            syntax_cases_buf17, syntax_cases_expected17,
            {
                return_code(JSTokenizer::BAD_TOKEN),
                expected_cursor_pos(23)
            });

    SECTION("escaped LF-CR sequence within literal")
        test_normalization_noident(
            syntax_cases_buf18, syntax_cases_expected18,
            {
                return_code(JSTokenizer::BAD_TOKEN),
                expected_cursor_pos(25)
            });

    SECTION("escaped LF within regex literal")
        test_normalization_noident(
            syntax_cases_buf19, syntax_cases_expected19,
            {
                return_code(JSTokenizer::BAD_TOKEN),
                expected_cursor_pos(23)
            });

    SECTION("escaped CR-LF within regex literal")
    {
        test_normalization_noident(syntax_cases_buf20, syntax_cases_expected20,
            {
                return_code(JSTokenizer::BAD_TOKEN),
                expected_cursor_pos(23),
            });
    }
    SECTION("explicit LF within regex literal")
    {
        test_normalization_noident(syntax_cases_buf26, syntax_cases_expected26,
            {
                return_code(JSTokenizer::BAD_TOKEN),
                expected_cursor_pos(23),
            });
    }
}

TEST_CASE("braces overflow", "[JSNormalizer]")
{
    SECTION("exceeding template literal limit")
        test_normalization_noident(
            syntax_cases_buf23, syntax_cases_expected23,
            {
                return_code(JSTokenizer::TEMPLATE_NESTING_OVERFLOW),
                expected_cursor_pos(15)
            });

    SECTION("exceeding regex literal limit")
        test_normalization_noident(
            syntax_cases_buf24, syntax_cases_expected24,
            {
                return_code(JSTokenizer::TEMPLATE_NESTING_OVERFLOW),
                expected_cursor_pos(30)
            });

}

static const char asi_cases_buf0[] =
    "array[0]\n{}";

static const char asi_cases_expected0[] =
    "array[0];{}";

static const char asi_cases_buf1[] =
    "array[0]\ntrue";

static const char asi_cases_expected1[] =
    "array[0];true";

static const char asi_cases_buf2[] =
    "array[0]\n++";

static const char asi_cases_expected2[] =
    "array[0];++";

static const char asi_cases_buf3[] =
    "array[0]\ncontinue";

static const char asi_cases_expected3[] =
    "array[0];continue";

static const char asi_cases_buf4[] =
    "array[0]\nvar b;";

static const char asi_cases_expected4[] =
    "array[0];var b;";

static const char asi_cases_buf5[] =
    "func()\ntrue";

static const char asi_cases_expected5[] =
    "func();true";

static const char asi_cases_buf6[] =
    "func()\n++";

static const char asi_cases_expected6[] =
    "func();++";

static const char asi_cases_buf7[] =
    "func()\ncontinue";

static const char asi_cases_expected7[] =
    "func();continue";

static const char asi_cases_buf8[] =
    "func()\nvar b;";

static const char asi_cases_expected8[] =
    "func();var b;";

static const char asi_cases_buf9[] =
    "1024\n{}";

static const char asi_cases_expected9[] =
    "1024;{}";

static const char asi_cases_buf10[] =
    "1024\ntrue";

static const char asi_cases_expected10[] =
    "1024;true";

static const char asi_cases_buf11[] =
    "1024\n++";

static const char asi_cases_expected11[] =
    "1024;++";

static const char asi_cases_buf12[] =
    "1024\ncontinue";

static const char asi_cases_expected12[] =
    "1024;continue";

static const char asi_cases_buf13[] =
    "1024\nvar b;";

static const char asi_cases_expected13[] =
    "1024;var b;";

static const char asi_cases_buf14[] =
    "++\n{}";

static const char asi_cases_expected14[] =
    "++;{}";

static const char asi_cases_buf15[] =
    "++\n[1,2,3]";

static const char asi_cases_expected15[] =
    "++;[1,2,3]";

static const char asi_cases_buf16[] =
    "++\ntrue";

static const char asi_cases_expected16[] =
    "++;true";

static const char asi_cases_buf17[] =
    "++\n++";

static const char asi_cases_expected17[] =
    "++;++";

static const char asi_cases_buf18[] =
    "++\ncontinue";

static const char asi_cases_expected18[] =
    "++;continue";

static const char asi_cases_buf19[] =
    "++\nvar b;";

static const char asi_cases_expected19[] =
    "++;var b;";

static const char asi_cases_buf20[] =
    "return\n{}";

static const char asi_cases_expected20[] =
    "return;{}";

static const char asi_cases_buf21[] =
    "return\n[1,2,3]";

static const char asi_cases_expected21[] =
    "return;[1,2,3]";

static const char asi_cases_buf22[] =
    "return\n+a";

static const char asi_cases_expected22[] =
    "return;+a";

static const char asi_cases_buf23[] =
    "return\ntrue";

static const char asi_cases_expected23[] =
    "return;true";

static const char asi_cases_buf24[] =
    "return\n++";

static const char asi_cases_expected24[] =
    "return;++";

static const char asi_cases_buf25[] =
    "return\ncontinue";

static const char asi_cases_expected25[] =
    "return;continue";

static const char asi_cases_buf26[] =
    "return\nvar b;";

static const char asi_cases_expected26[] =
    "return;var b;";

TEST_CASE("automatic semicolon insertion", "[JSNormalizer]")
{
    SECTION("group_4 to group_1")
    {
        test_normalization_noident(
            asi_cases_buf0,
            asi_cases_expected0
        );
    }

    SECTION("group_4 to group_7")
    {
        test_normalization_noident(
            asi_cases_buf1,
            asi_cases_expected1
        );
    }

    SECTION("group_4 to group_8")
    {
        test_normalization_noident(
            asi_cases_buf2,
            asi_cases_expected2
        );
    }

    SECTION("group_4 to group_9")
    {
        test_normalization_noident(
            asi_cases_buf3,
            asi_cases_expected3
        );
    }

    SECTION("group_4 to group_10")
    {
        test_normalization_noident(
            asi_cases_buf4,
            asi_cases_expected4
        );
    }

    SECTION("group_5 to group_7")
    {
        test_normalization_noident(
            asi_cases_buf5,
            asi_cases_expected5
        );
    }

    SECTION("group_5 to group_8")
    {
        test_normalization_noident(
            asi_cases_buf6,
            asi_cases_expected6
        );
    }

    SECTION("group_5 to group_9")
    {
        test_normalization_noident(
            asi_cases_buf7,
            asi_cases_expected7
        );
    }

    SECTION("group_5 to group_10")
    {
        test_normalization_noident(
            asi_cases_buf8,
            asi_cases_expected8
        );
    }

    SECTION("group_7 to group_1")
    {
        test_normalization_noident(
            asi_cases_buf9,
            asi_cases_expected9
        );
    }

    SECTION("group_7 to group_7")
    {
        test_normalization_noident(
            asi_cases_buf10,
            asi_cases_expected10
        );
    }

    SECTION("group_7 to group_8")
    {
        test_normalization_noident(
            asi_cases_buf11,
            asi_cases_expected11
        );
    }

    SECTION("group_7 to group_9")
    {
        test_normalization_noident(
            asi_cases_buf12,
            asi_cases_expected12
        );
    }

    SECTION("group_7 to group_10")
    {
        test_normalization_noident(
            asi_cases_buf13,
            asi_cases_expected13
        );
    }

    SECTION("group_8 to group_1")
    {
        test_normalization_noident(
            asi_cases_buf14,
            asi_cases_expected14
        );
    }

    SECTION("group_8 to group_3")
    {
        test_normalization_noident(
            asi_cases_buf15,
            asi_cases_expected15
        );
    }

    SECTION("group_8 to group_7")
    {
        test_normalization_noident(
            asi_cases_buf16,
            asi_cases_expected16
        );
    }

    SECTION("group_8 to group_8")
    {
        test_normalization_noident(
            asi_cases_buf17,
            asi_cases_expected17
        );
    }

    SECTION("group_8 to group_9")
    {
        test_normalization_noident(
            asi_cases_buf18,
            asi_cases_expected18
        );
    }

    SECTION("group_8 to group_10")
    {
        test_normalization_noident(
            asi_cases_buf19,
            asi_cases_expected19
        );
    }

    SECTION("group_9 to group_1")
    {
        test_normalization_noident(
            asi_cases_buf20,
            asi_cases_expected20
        );
    }

    SECTION("group_9 to group_3")
    {
        test_normalization_noident(
            asi_cases_buf21,
            asi_cases_expected21
        );
    }

    SECTION("group_9 to group_6")
    {
        test_normalization_noident(
            asi_cases_buf22,
            asi_cases_expected22
        );
    }

    SECTION("group_9 to group_7")
    {
        test_normalization_noident(
            asi_cases_buf23,
            asi_cases_expected23
        );
    }

    SECTION("group_9 to group_8")
    {
        test_normalization_noident(
            asi_cases_buf24,
            asi_cases_expected24
        );
    }

    SECTION("group_9 to group_9")
    {
        test_normalization_noident(
            asi_cases_buf25,
            asi_cases_expected25
        );
    }

    SECTION("group_9 to group_10")
    {
        test_normalization_noident(
            asi_cases_buf26,
            asi_cases_expected26
        );
    }
}

TEST_CASE("endings", "[JSNormalizer]")
{
    SECTION("script closing tag is present", "[JSNormalizer]")
    {
        const char src[] =
            "var a = 1 ;\n" // 12 bytes
            "var b = 2 ;\n" // 12 bytes
            "</script>\n"   // ptr_offset is here = 33
            "var c = 3 ;\n";
        const int ptr_offset = 33;
        const char expected[] = "var a=1;var b=2;";

        test_normalization_noident(src, expected,
            {return_code(JSTokenizer::SCRIPT_ENDED), expected_cursor_pos(ptr_offset)});
    }
    SECTION("depth reached", "[JSNormalizer]")
    {
        std::string source = "var abc = 123;\n\r";
        std::string expected = "var abc";
        int depth = 7;

        auto norm = default_config.derive({norm_depth(depth), normalize_identifiers(false),
            use_expected_for_last_pdu(true)});

        JSTokenizerTester tester(norm);

        tester.do_pdu(source);
        tester.check_output(expected);
        tester.run_checks({return_code(JSTokenizer::EOS), expected_cursor_pos(depth)});

        tester.do_pdu(source);
        tester.check_output("");
        tester.run_checks({return_code(JSTokenizer::EOS), expected_cursor_pos(source.length())});
    }
}

static const char unexpected_tag_buf0[] =
    "var a = 1;\n"
    "<script>\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected0[] =
    "var a=1;<script>var b=2;";

static const char unexpected_tag_buf1[] =
    "var a = 1;\n"
    "<script type=application/javascript>\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected1[] =
    "var a=1;<script type=application/javascript>var b=2;";

static const char unexpected_tag_buf2[] =
    "var a = 1;\n"
    "var str = '<script> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected2[] =
    "var a=1;var str='<script> something';var b=2;";

static const char unexpected_tag_buf3[] =
    "var a = 1;\n"
    "var str = 'something <script> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected3[] =
    "var a=1;var str='something <script> something';var b=2;";

static const char unexpected_tag_buf4[] =
    "var a = 1;\n"
    "var str = 'something <script>';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected4[] =
    "var a=1;var str='something <script>';var b=2;";

static const char unexpected_tag_buf5[] =
    "var a = 1;\n"
    "var str = '</script> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected5[] =
    "var a=1;var str='";

static const char unexpected_tag_expected5_ext[] =
    "var a=1;var str='</script> something';var b=2;";

static const char unexpected_tag_buf6[] =
    "var a = 1;\n"
    "var str = 'something </script> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected6[] =
    "var a=1;var str='something ";

static const char unexpected_tag_expected6_ext[] =
    "var a=1;var str='something </script> something';var b=2;";

static const char unexpected_tag_buf7[] =
    "var a = 1;\n"
    "var str = 'something </script>';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected7[] =
    "var a=1;var str='something ";

static const char unexpected_tag_expected7_ext[] =
    "var a=1;var str='something </script>';var b=2;";

static const char unexpected_tag_buf8[] =
    "var a = 1;\n"
    "var str = 'something \\<script> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected8[] =
    "var a=1;var str='something \\<script> something';var b=2;";

static const char unexpected_tag_buf9[] =
    "var a = 1;\n"
    "var str = 'something \\<\\/script\\> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected9[] =
    "var a=1;var str='something \\<\\/script\\> something';var b=2;";

static const char unexpected_tag_expected9_ext[] =
    "var a=1;var str='something \\<\\/script\\> something';var b=2;";

static const char unexpected_tag_buf10[] =
    "var a = 1;\n"
    "//<script> something\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected10[] =
    "var a=1;var b=2;";

static const char unexpected_tag_buf11[] =
    "var a = 1;\n"
    "//something <script> something\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected11[] =
    "var a=1;var b=2;";

static const char unexpected_tag_buf12[] =
    "var a = 1;\n"
    "//something <script>\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected12[] =
    "var a=1;var b=2;";

static const char unexpected_tag_buf13[] =
    "var a = 1;\n"
    "/*<script> something*/\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected13[] =
    "var a=1;var b=2;";

static const char unexpected_tag_buf14[] =
    "var a = 1;\n"
    "/*something <script> something*/\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected14[] =
    "var a=1;var b=2;";

static const char unexpected_tag_buf15[] =
    "var a = 1;\n"
    "/*something <script>*/\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected15[] =
    "var a=1;var b=2;";

static const char unexpected_tag_buf16[] =
    "var a = 1;\n"
    "//</script> something\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected16[] =
    "var a=1;";

static const char unexpected_tag_expected16_ext[] =
    "var a=1;var b=2;";

static const char unexpected_tag_buf17[] =
    "var a = 1;\n"
    "<!--something </script> something//-->\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected17[] =
    "var a=1;";

static const char unexpected_tag_expected17_ext[] =
    "var a=1;var b=2;";

static const char unexpected_tag_buf18[] =
    "var a = 1;\n"
    "//something </script>\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected18[] =
    "var a=1;";

static const char unexpected_tag_expected18_ext[] =
    "var a=1;var b=2;";

static const char unexpected_tag_buf19[] =
    "var a = 1;\n"
    "/*</script>\n"
    "something*/\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected19[] =
    "var a=1;";

static const char unexpected_tag_expected19_ext[] =
    "var a=1;var b=2;";

static const char unexpected_tag_buf20[] =
    "var a = 1;\n"
    "/*something\n"
    "</script>\n"
    "something*/\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected20[] =
    "var a=1;";

static const char unexpected_tag_expected20_ext[] =
    "var a=1;var b=2;";

static const char unexpected_tag_buf21[] =
    "var a = 1;\n"
    "/*something\n"
    "</script>*/\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected21[] =
    "var a=1;";

static const char unexpected_tag_expected21_ext[] =
    "var a=1;var b=2;";

static const char unexpected_tag_buf22[] =
    "var a = 1;\n"
    "var str = 'script somescript /script something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected22[] =
    "var a=1;var str='script somescript /script something';var b=2;";

static const char unexpected_tag_buf23[] =
    "var a = 1;\n"
    "var str = 'script somescript /script something <script>';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected23[] =
    "var a=1;var str='script somescript /script something <script>';var b=2;";

static const char unexpected_tag_buf24[] =
    "var a = 1;\n"
    "var str = 'something <sCrIpT>';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected24[] =
    "var a=1;var str='something <sCrIpT>';var b=2;";

static const char unexpected_tag_buf25[] =
    "var template = ` <script> ` ;";

static const char unexpected_tag_expected25[] =
    "var template=` <script> `;";

static const char unexpected_tag_buf26[] =
    "var regex = / <script> / ;";

static const char unexpected_tag_expected26[] =
    "var regex=/ <script> /;";

static const char unexpected_tag_buf27[] =
    "var template = ` </script> `;";

static const char unexpected_tag_expected27[] =
    "var template=` ";

static const char unexpected_tag_expected27_ext[] =
    "var template=` </script> `;";

static const char unexpected_tag_buf28[] =
    "var regex = / </script> /;/";

static const char unexpected_tag_expected28[] =
    "var regex=/ ";

static const char unexpected_tag_expected28_ext[] =
    "var regex=/ </s cript>/;/";

static const char unexpected_tag_buf29[] =
    "var a = 5 </script>/";

static const char unexpected_tag_expected29[] =
    "var a=5";

static const char unexpected_tag_expected29_ext[] =
    "var a=5</script>/";

TEST_CASE("nested script tags", "[JSNormalizer]")
{
    SECTION("explicit open tag - simple")
    {
        test_normalization_noident(
            unexpected_tag_buf0, unexpected_tag_expected0,
            {check_open_tag(true)});
    }
    SECTION("explicit open tag - complex")
    {
        test_normalization_noident(
            unexpected_tag_buf1, unexpected_tag_expected1,
            {check_open_tag(true)});
    }
    SECTION("open tag within literal - start")
    {
        test_normalization_noident(
            unexpected_tag_buf2, unexpected_tag_expected2,
            {check_open_tag(false)});
    }
    SECTION("open tag within literal - mid")
    {
        test_normalization_noident(
            unexpected_tag_buf3, unexpected_tag_expected3,
            {check_open_tag(false)});
    }
    SECTION("open tag within literal - end")
    {
        test_normalization_noident(
            unexpected_tag_buf4, unexpected_tag_expected4,
            {check_open_tag(false)});
    }
    SECTION("close tag within literal - start")
        test_normalization_noident(
            unexpected_tag_buf5, unexpected_tag_expected5,
            {
                return_code(JSTokenizer::CLOSING_TAG),
                expected_cursor_pos(31),
                normalize_identifiers(false)
            });

    SECTION("close tag within literal - mid")
        test_normalization_noident(
            unexpected_tag_buf6, unexpected_tag_expected6,
            {
                return_code(JSTokenizer::CLOSING_TAG),
                expected_cursor_pos(41)
            });

    SECTION("close tag within literal - end")
        test_normalization_noident(
            unexpected_tag_buf7, unexpected_tag_expected7,
            {
                return_code(JSTokenizer::CLOSING_TAG),
                expected_cursor_pos(41)
            });

    SECTION("open tag within literal - escaped")
    {
        test_normalization_noident(
            unexpected_tag_buf8, unexpected_tag_expected8,
            {check_open_tag(false)});
    }
    SECTION("close tag within literal - escaped")
    {
        test_normalization_noident(
            unexpected_tag_buf9,
            unexpected_tag_expected9
        );
    }
    SECTION("open tag within single-line comment - start")
    {
        test_normalization_noident(
            unexpected_tag_buf10, unexpected_tag_expected10,
            {check_open_tag(true)});
    }
    SECTION("open tag within single-line comment - mid")
    {
        test_normalization_noident(
            unexpected_tag_buf11, unexpected_tag_expected11,
            {check_open_tag(true)});
    }
    SECTION("open tag within single-line comment - end")
    {
        test_normalization_noident(
            unexpected_tag_buf12, unexpected_tag_expected12,
            {check_open_tag(true)});
    }
    SECTION("open tag within multi-line comment - start")
    {
        test_normalization_noident(
            unexpected_tag_buf13, unexpected_tag_expected13,
            {check_open_tag(true)});
    }
    SECTION("open tag within multi-line comment - mid")
    {
        test_normalization_noident(
            unexpected_tag_buf14, unexpected_tag_expected14,
            {check_open_tag(true)});
    }
    SECTION("open tag within multi-line comment - end")
    {
        test_normalization_noident(
            unexpected_tag_buf15, unexpected_tag_expected15,
            {check_open_tag(true)});
    }
    SECTION("close tag within single-line comment - start")
        test_normalization_noident(
            unexpected_tag_buf16, unexpected_tag_expected16,
            {
                return_code(JSTokenizer::SCRIPT_ENDED),
                expected_cursor_pos(22)
            });

    SECTION("close tag within single-line comment - mid")
        test_normalization_noident(
            unexpected_tag_buf17, unexpected_tag_expected17,
            {
                return_code(JSTokenizer::SCRIPT_ENDED),
                expected_cursor_pos(34)
            });

    SECTION("close tag within single-line comment - end")
        test_normalization_noident(
            unexpected_tag_buf18, unexpected_tag_expected18,
            {
                return_code(JSTokenizer::SCRIPT_ENDED),
                expected_cursor_pos(32)
            });

    SECTION("close tag within multi-line comment - start")
        test_normalization_noident(
            unexpected_tag_buf19, unexpected_tag_expected19,
            {
                return_code(JSTokenizer::CLOSING_TAG),
                expected_cursor_pos(22)
            });

    SECTION("close tag within multi-line comment - mid")
        test_normalization_noident(
            unexpected_tag_buf20, unexpected_tag_expected20,
            {
                return_code(JSTokenizer::CLOSING_TAG),
                expected_cursor_pos(32)
            });

    SECTION("close tag within multi-line comment - end")
        test_normalization_noident(
            unexpected_tag_buf21, unexpected_tag_expected21,
            {
                return_code(JSTokenizer::CLOSING_TAG),
                expected_cursor_pos(32)
            });

    SECTION("multiple patterns - not matched")
    {
        test_normalization_noident(
            unexpected_tag_buf22,
            unexpected_tag_expected22
        );
    }
    SECTION("multiple patterns - matched")
    {
        test_normalization_noident(
            unexpected_tag_buf23, unexpected_tag_expected23,
            {check_open_tag(false)});
    }
    SECTION("mixed lower and upper case")
    {
        test_normalization_noident(
            unexpected_tag_buf24, unexpected_tag_expected24,
            {check_open_tag(false)});
    }
    SECTION("opening tag within template literal")
    {
        test_normalization_noident(
            unexpected_tag_buf25, unexpected_tag_expected25,
            {check_open_tag(true)});
    }
    SECTION("opening tag within regex literal")
    {
        test_normalization_noident(
            unexpected_tag_buf26, unexpected_tag_expected26,
            {check_open_tag(true)});
    }
    SECTION("closing tag within template literal")
    {
        test_normalization_noident(unexpected_tag_buf27, unexpected_tag_expected27,
            {
                return_code(JSTokenizer::CLOSING_TAG),
                expected_cursor_pos(26),
            });
    }
    SECTION("closing tag within regex literal")
    {
        test_normalization_noident(unexpected_tag_buf28, unexpected_tag_expected28,
            {
                return_code(JSTokenizer::CLOSING_TAG),
                expected_cursor_pos(23),
            });
    }
    SECTION("closing tag from regex literal expression")
    {
        test_normalization_noident(unexpected_tag_buf29, unexpected_tag_expected29,
            {
                return_code(JSTokenizer::SCRIPT_ENDED),
                expected_cursor_pos(19),
            });
    }
}

TEST_CASE("opening tag sequence", "[JSNormalizer]")
{
    SECTION("incomplete")
    {
        const char src[] = "<script";
        const char exp[] = "<script";

        test_normalization_noident(
            src, exp,
            {check_open_tag(false)});
    }
    SECTION("valid 1")
    {
        const char src[] = "<scripts";
        const char exp[] = "<scripts";

        test_normalization_noident(
            src, exp,
            {check_open_tag(false)});
    }
    SECTION("valid 2")
    {
        const char src[] = "<script.";
        const char exp[] = "<script.";

        test_normalization_noident(
            src, exp,
            {check_open_tag(false)});
    }
    SECTION("tabulation")
    {
        const char src[] = "<script\x9";
        const char exp[] = "<script";

        test_normalization_noident(
            src, exp,
            {check_open_tag(true)});
    }
    SECTION("line feed")
    {
        const char src[] = "<script\xA";
        const char exp[] = "<script";

        test_normalization_noident(
            src, exp,
            {check_open_tag(true)});
    }
    SECTION("form feed")
    {
        const char src[] = "<script\xC";
        const char exp[] = "<script";

        test_normalization_noident(
            src, exp,
            {check_open_tag(true)});
    }
    SECTION("space")
    {
        const char src[] = "<script\x20";
        const char exp[] = "<script";

        test_normalization_noident(
            src, exp,
            {check_open_tag(true)});
    }
    SECTION("solidus")
    {
        const char src[] = "<script\x2F";
        const char exp[] = "<script\x2F";

        test_normalization_noident(
            src, exp,
            {check_open_tag(true)});
    }
    SECTION("greater than")
    {
        const char src[] = "<script\x3E";
        const char exp[] = "<script\x3E";

        test_normalization_noident(
            src, exp,
            {check_open_tag(true)});
    }
}

TEST_CASE("nested script tags in an external script", "[JSNormalizer]")
{
    SECTION("explicit open tag - simple")
    {
        test_normalization_noident(
            unexpected_tag_buf0, unexpected_tag_expected0,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("explicit open tag - complex")
    {
        test_normalization_noident(
            unexpected_tag_buf1, unexpected_tag_expected1,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("open tag within literal - start")
    {
        test_normalization_noident(
            unexpected_tag_buf2, unexpected_tag_expected2,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("open tag within literal - mid")
    {
        test_normalization_noident(
            unexpected_tag_buf3, unexpected_tag_expected3,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("open tag within literal - end")
    {
        test_normalization_noident(
            unexpected_tag_buf4, unexpected_tag_expected4,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("close tag within literal - start")
    {
        test_normalization_noident(
            unexpected_tag_buf5, unexpected_tag_expected5_ext,
            {normalize_as_external(true)});
    }
    SECTION("close tag within literal - mid")
    {
        test_normalization_noident(
            unexpected_tag_buf6, unexpected_tag_expected6_ext,
            {normalize_as_external(true)});
    }
    SECTION("close tag within literal - end")
    {
        test_normalization_noident(
            unexpected_tag_buf7, unexpected_tag_expected7_ext,
            {normalize_as_external(true)});
    }
    SECTION("open tag within literal - escaped")
    {
        test_normalization_noident(
            unexpected_tag_buf8, unexpected_tag_expected8,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("close tag within literal - escaped")
    {
        test_normalization_noident(
            unexpected_tag_buf9, unexpected_tag_expected9_ext,
            {normalize_as_external(true)});
    }
    SECTION("open tag within single-line comment - start")
    {
        test_normalization_noident(
            unexpected_tag_buf10, unexpected_tag_expected10,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("open tag within single-line comment - mid")
    {
        test_normalization_noident(
            unexpected_tag_buf11, unexpected_tag_expected11,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("open tag within single-line comment - end")
    {
        test_normalization_noident(
            unexpected_tag_buf12, unexpected_tag_expected12,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("open tag within multi-line comment - start")
    {
        test_normalization_noident(
            unexpected_tag_buf13, unexpected_tag_expected13,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("open tag within multi-line comment - mid")
    {
        test_normalization_noident(
            unexpected_tag_buf14, unexpected_tag_expected14,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("open tag within multi-line comment - end")
    {
        test_normalization_noident(
            unexpected_tag_buf15, unexpected_tag_expected15,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("close tag within single-line comment - start")
    {
        test_normalization_noident(
            unexpected_tag_buf16, unexpected_tag_expected16_ext,
            {normalize_as_external(true)});
    }
    SECTION("close tag within single-line comment - mid")
    {
        test_normalization_noident(
            unexpected_tag_buf17, unexpected_tag_expected17_ext,
            {normalize_as_external(true)});
    }
    SECTION("close tag within single-line comment - end")
    {
        test_normalization_noident(
            unexpected_tag_buf18, unexpected_tag_expected18_ext,
            {normalize_as_external(true)});
    }
    SECTION("close tag within multi-line comment - start")
    {
        test_normalization_noident(
            unexpected_tag_buf19, unexpected_tag_expected19_ext,
            {normalize_as_external(true)});
    }
    SECTION("close tag within multi-line comment - mid")
    {
        test_normalization_noident(
            unexpected_tag_buf20, unexpected_tag_expected20_ext,
            {normalize_as_external(true)});
    }
    SECTION("close tag within multi-line comment - end")
    {
        test_normalization_noident(
            unexpected_tag_buf21, unexpected_tag_expected21_ext,
            {normalize_as_external(true)});
    }
    SECTION("multiple patterns - not matched")
    {
        test_normalization_noident(
            unexpected_tag_buf22, unexpected_tag_expected22,
            {normalize_as_external(true)});
    }
    SECTION("multiple patterns - matched")
    {
        test_normalization_noident(
            unexpected_tag_buf23, unexpected_tag_expected23,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("mixed lower and upper case")
    {
        test_normalization_noident(
            unexpected_tag_buf24, unexpected_tag_expected24,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("opening tag within template literal")
    {
        test_normalization_noident(
            unexpected_tag_buf25, unexpected_tag_expected25,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("opening tag within regex literal")
    {
        test_normalization_noident(
            unexpected_tag_buf26, unexpected_tag_expected26,
            {
                check_open_tag(false),
                normalize_as_external(true)
            });
    }
    SECTION("closing tag within template literal")
    {
        test_normalization_noident(unexpected_tag_buf27, unexpected_tag_expected27_ext,
            {normalize_as_external(true)});
    }
    SECTION("closing tag within regex literal")
    {
        test_normalization_noident(unexpected_tag_buf28, unexpected_tag_expected28_ext,
            {normalize_as_external(true)});
    }
    SECTION("closing tag from regex literal expression")
    {
        test_normalization_noident(unexpected_tag_buf29, unexpected_tag_expected29_ext,
            {normalize_as_external(true), check_closing_tag(true)});
    }
}

TEST_CASE("split between tokens", "[JSNormalizer]")
{
    auto norm = default_config.derive({normalize_identifiers(false), use_expected_for_last_pdu(true)});

    SECTION("operator string")
    {
        const char dat1[] = "var s = ";
        const char dat2[] = "'string';";
        const char exp1[] = "var s=";
        const char exp2[] = "'string';";
        const char exp[] = "var s='string';";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("operator number")
    {
        const char dat1[] = "a = 5 +";
        const char dat2[] = "b + c;";
        const char exp1[] = "a=5+";
        const char exp2[] = "b+c;";
        const char exp[] = "a=5+b+c;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("comment function")
    {
        const char dat1[] = "// no comments\n";
        const char dat2[] = "foo(bar, baz);";
        const char exp1[] = "";
        const char exp2[] = "foo(bar,baz);";
        const char exp[] = "foo(bar,baz);";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("operator identifier")
    {
        const char dat1[] = "var ";
        const char dat2[] = "a = ";
        const char dat3[] = "b  ;";
        const char exp1[] = "var";
        const char exp2[] = " a=";
        const char exp3[] = "b;";
        const char exp[] = "var a=b;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
                {dat3, exp3},
            });

        norm.test_normalization_combined({dat1, dat2, dat3}, exp);
    }
    SECTION("complete open tag - identifier")
    {
        const char dat1[] = " ( a <script> ";
        const char dat2[] = " b ) ";
        const char exp1[] = "(a<script>";
        const char exp2[] = "b)";
        const char exp[] = "(a<script>b)";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("incomplete open tag - identifier")
    {
        const char dat1[] = " <script  ";
        const char dat2[] = " a ; ";
        const char exp1[] = "<script";
        const char exp2[] = " a;";
        const char exp[] = "<script a;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("incomplete open tag - operator")
    {
        const char dat1[] = " ( a <script  ";
        const char dat2[] = " ) ";
        const char exp1[] = "(a<script";
        const char exp2[] = ")";
        const char exp[] = "(a<script)";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("identifier - complete open tag")
    {
        const char dat1[] = " ( a  ";
        const char dat2[] = " <script> b ) ";
        const char exp1[] = "(a";
        const char exp2[] = "<script>b)";
        const char exp[] = "(a<script>b)";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("identifier - incomplete open tag")
    {
        const char dat1[] = " ( a  ";
        const char dat2[] = " <script  ) ";
        const char exp1[] = "(a";
        const char exp2[] = "<script)";
        const char exp[] = "(a<script)";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("operator - incomplete open tag")
    {
        const char dat1[] = " ( a  < ";
        const char dat2[] = " <script ) ";
        const char exp1[] = "(a<";
        const char exp2[] = "<script)";
        const char exp[] = "(a<<script)";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("identifier - incomplete open tag as a comparison")
    {
        const char dat1[] = " ( a  < ";
        const char dat2[] = " script ) ";
        const char exp1[] = "(a<";
        const char exp2[] = "script)";
        const char exp[] = "(a<script)";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("identifier - complete open tag as a comparison")
    {
        const char dat1[] = " ( a  <";
        const char dat2[] = "script ) ";
        const char exp1[] = "(a<";
        const char exp2[] = "<script)";
        const char exp[] = "(a<script)";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("complete regex (1 parsing group) - identifier")
    {
        const char dat1[] = "/ss/,";
        const char dat2[] = " a ;";
        const char exp1[] = "/ss/,";
        const char exp2[] = "a;";
        const char exp[] = "/ss/,a;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("complete regex (2 parsing groups) - identifier")
    {
        const char dat1[] = "/\\s/,";
        const char dat2[] = " a ;";
        const char exp1[] = "/\\s/,";
        const char exp2[] = "a;";
        const char exp[] = "/\\s/,a;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("complete regex (not the first) - identifier")
    {
        const char dat1[] = ",/\\s/,";
        const char dat2[] = " a ;";
        const char exp1[] = ",/\\s/,";
        const char exp2[] = "a;";
        const char exp[] = ",/\\s/,a;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
}

TEST_CASE("split in comments", "[JSNormalizer]")
{
    auto norm = default_config.derive({normalize_identifiers(false), use_expected_for_last_pdu(true)});

    SECTION("/ /")
    {
        const char dat1[] = "/";
        const char dat2[] = "/comment\n";
        const char exp1[] = "/";
        const char exp2[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("/ / msg")
    {
        const char dat1[] = "//";
        const char dat2[] = "comment\n";
        const char exp1[] = "";
        const char exp2[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("/ / LF")
    {
        const char dat1[] = "//comment";
        const char dat2[] = "\n";
        const char exp1[] = "";
        const char exp2[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }

    SECTION("/ *")
    {
        const char dat1[] = "/";
        const char dat2[] = "* comment */";
        const char exp1[] = "/";
        const char exp2[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("/ * msg")
    {
        const char dat1[] = "/* t";
        const char dat2[] = "ext */";
        const char exp1[] = "";
        const char exp2[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("* /")
    {
        const char dat1[] = "/* comment *";
        const char dat2[] = "/";
        const char exp1[] = "";
        const char exp2[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("/ * msg * /")
    {
        const char dat1[] = "/";
        const char dat2[] = "* comment *";
        const char dat3[] = "/";
        const char exp1[] = "/";
        const char exp2[] = "";
        const char exp3[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
                {dat3, exp3},
            });

        norm.test_normalization_combined({dat1, dat2, dat3}, exp);
    }

    SECTION("< !--")
    {
        const char dat1[] = "<";
        const char dat2[] = "!-- comment\n";
        const char exp1[] = "<";
        const char exp2[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("<! --")
    {
        const char dat1[] = "<!";
        const char dat2[] = "-- comment\n";
        const char exp1[] = "<!";
        const char exp2[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("<!- -")
    {
        const char dat1[] = "<!-";
        const char dat2[] = "- comment\n";
        const char exp1[] = "<!-";
        const char exp2[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("<!-- msg")
    {
        const char dat1[] = "<!--";
        const char dat2[] = "comment\n";
        const char exp1[] = "";
        const char exp2[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("<! -- msg")
    {
        const char dat1[] = "<";
        const char dat2[] = "!-";
        const char dat3[] = "-comment\n";
        const char exp1[] = "<";
        const char exp2[] = "!-";
        const char exp3[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
                {dat3, exp3},
            });

        norm.test_normalization_combined({dat1, dat2, dat3}, exp);
    }
}

TEST_CASE("split in opening tag", "[JSNormalizer]")
{
    auto norm = default_config.derive({normalize_identifiers(false), use_expected_for_last_pdu(true)});

    SECTION("< script")
    {
        const char dat1[] = "<";
        const char dat2[] = "script>";
        const char exp1[] = "<";
        const char exp2[] = "<script>";
        const char exp[] = "<script>";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("str='<s cript'")
    {
        const char dat1[] = "var str ='<s";
        const char dat2[] = "cript>';";
        const char exp1[] = "var str='<s";
        const char exp2[] = "<script>';";
        const char exp[]  = "var str='<script>';";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("str='<scrip t'")
    {
        const char dat1[] = "var str ='<scrip";
        const char dat2[] = "t>';";
        const char exp1[] = "var str='<scrip";
        const char exp2[] = "<script>';";
        const char exp[] = "var str='<script>';";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("< scr ipt")
    {
        const char dat1[] = "<";
        const char dat2[] = "scr";
        const char dat3[] = "ipt>";
        const char exp1[] = "<";
        const char exp2[] = "scr";
        const char exp3[] = "<script>";
        const char exp[] = "<script>";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
                {dat3, exp3},
            });

        norm.test_normalization_combined({dat1, dat2, dat3}, exp);
    }
    SECTION("str='<sc rip t'")
    {
        const char dat1[] = "var str =\"<sc";
        const char dat2[] = "rip";
        const char dat3[] = "t>\";";
        const char exp1[] = "var str=\"<sc";
        const char exp2[] = "scrip";
        const char exp3[] = "<script>\";";
        const char exp[] = "var str=\"<script>\";";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
                {dat3, exp3},
            });

        norm.test_normalization_combined({dat1, dat2, dat3}, exp);
    }
}

TEST_CASE("split in closing tag", "[JSNormalizer]")
{
    auto norm = default_config.derive({normalize_identifiers(false), use_expected_for_last_pdu(true)});

    SECTION("< /script>")
    {
        const char dat1[] = "<";
        const char dat2[] = "/script>";
        const char exp1[] = "<";
        const char exp2[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            },
            {return_code(JSTokenizer::SCRIPT_ENDED)});

        norm.test_normalization_combined({dat1, dat2}, exp,
            {return_code(JSTokenizer::SCRIPT_ENDED)});
    }
    SECTION("</script >")
    {
        const char dat1[] = "</script";
        const char dat2[] = ">";
        const char exp1[] = "</script";
        const char exp2[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            },
            {return_code(JSTokenizer::SCRIPT_ENDED)});

        norm.test_normalization_combined({dat1, dat2}, exp,
            {return_code(JSTokenizer::SCRIPT_ENDED)});
    }
    SECTION("str='</ script>'")
    {
        const char dat1[] = "var str ='</";
        const char dat2[] = "script>';";
        const char exp1[] = "var str='</";
        const char exp2[] = "";
        const char exp[] = "var str='";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            },
            {return_code(JSTokenizer::CLOSING_TAG)});

        norm.test_normalization_combined({dat1, dat2}, exp,
            {return_code(JSTokenizer::CLOSING_TAG)});
    }
    SECTION("str='</scrip t>'")
    {
        const char dat1[] = "var str ='</scrip";
        const char dat2[] = "t>';";
        const char exp1[] = "var str='</scrip";
        const char exp2[] = "";
        const char exp[] = "var str='";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            },
            {return_code(JSTokenizer::CLOSING_TAG)});

        norm.test_normalization_combined({dat1, dat2}, exp,
            {return_code(JSTokenizer::CLOSING_TAG)});
    }
    SECTION("</ scr ipt>")
    {
        const char dat1[] = "</";
        const char dat2[] = "scr";
        const char dat3[] = "ipt>";
        const char exp1[] = "</";
        const char exp2[] = "/scr";
        const char exp3[] = "";
        const char exp[] = "";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
                {dat3, exp3},
            },
            {return_code(JSTokenizer::SCRIPT_ENDED)});

        norm.test_normalization_combined({dat1, dat2, dat3}, exp,
            {return_code(JSTokenizer::SCRIPT_ENDED)});
    }
    SECTION("str='</sc rip t>'")
    {
        const char dat1[] = "var str =\"</sc";
        const char dat2[] = "rip";
        const char dat3[] = "t>\";";
        const char exp1[] = "var str=\"</sc";
        const char exp2[] = "/scrip";
        const char exp3[] = "";
        const char exp[] = "var str=\"";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
                {dat3, exp3},
            },
            {return_code(JSTokenizer::CLOSING_TAG)});

        norm.test_normalization_combined({dat1, dat2, dat3}, exp,
            {return_code(JSTokenizer::CLOSING_TAG)});
    }
    SECTION("::::</scr ipt >")
    {
        const char dat1[] = ":::: </scr";
        const char dat2[] = "ipt";
        const char dat3[] = ">";
        const char exp1[] = "::::</scr";
        const char exp2[] = "script";
        const char exp3[] = "";
        const char exp[] = "::::";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
                {dat3, exp3},
            },
            {return_code(JSTokenizer::SCRIPT_ENDED)});

        norm.test_normalization_combined({dat1, dat2, dat3}, exp,
            {return_code(JSTokenizer::SCRIPT_ENDED)});
    }
}

TEST_CASE("split in string literal", "[JSNormalizer]")
{
    auto norm = default_config.derive({normalize_identifiers(false), use_expected_for_last_pdu(true)});

    SECTION("\\ LF")
    {
        const char dat1[] = "var str =\"any\\";
        const char dat2[] = "\none\";";
        const char exp1[] = "var str=\"any\\";
        const char exp2[] = "one\";";
        const char exp[] = "var str=\"anyone\";";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("\\ CR")
    {
        const char dat1[] = "var str =\"any\\";
        const char dat2[] = "\rone\";";
        const char exp1[] = "var str=\"any\\";
        const char exp2[] = "one\";";
        const char exp[] = "var str=\"anyone\";";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("\\CR LF")
    {
        const char dat1[] = "var str =\"any\\\r";
        const char dat2[] = "\none\";";
        const char exp1[] = "var str=\"any";
        const char exp2[] = "one\";";
        const char exp[] = "var str=\"anyone\";";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("\\ CRLF")
    {
        const char dat1[] = "var str =\"any\\";
        const char dat2[] = "\r\none\";";
        const char exp1[] = "var str=\"any\\";
        const char exp2[] = "one\";";
        const char exp[] = "var str=\"anyone\";";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("\\ \"")
    {
        const char dat1[] = "var str =\"any\\";
        const char dat2[] = "\"one\";";
        const char exp1[] = "var str=\"any\\";
        const char exp2[] = "\\\"one\";";
        const char exp[] = "var str=\"any\\\"one\";";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("\\ \'")
    {
        const char dat1[] = "var str =\"any\\";
        const char dat2[] = "\'one\";";
        const char exp1[] = "var str=\"any\\";
        const char exp2[] = "\'one\";";
        const char exp[] = "var str=\"any\\\'one\";";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("\\ u1234tx")
    {
        const char dat1[] = "var str =\"any\\";
        const char dat2[] = "u1234tx\";";
        const char exp1[] = "var str=\"any\\";
        const char exp2[] = "\u1234tx\";";
        const char exp[] = "var str=\"any\u1234tx\";";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("\\u 1234tx")
    {
        const char dat1[] = "var str =\"any\\u";
        const char dat2[] = "1234tx\";";
        const char exp1[] = "var str=\"any\\u";
        const char exp2[] = "\u1234tx\";";
        const char exp[] = "var str=\"any\u1234tx\";";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
}

TEST_CASE("split in identifier", "[JSNormalizer]")
{
    auto norm = default_config.derive({normalize_identifiers(false), use_expected_for_last_pdu(true)});

    SECTION("abc def")
    {
        const char dat1[] = "var abc";
        const char dat2[] = "def = 5";
        const char exp1[] = "var abc";
        const char exp2[] = " abcdef=5";
        const char exp[] = "var abcdef=5";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("long identifier")
    {
        const char dat1[] = "var res = something + long_id_starts_here";
        const char dat2[] = "_long_id_ends_here;";
        const char exp1[] = "var res=something+long_id_starts_here";
        const char exp2[] = "long_id_starts_here_long_id_ends_here;";
        const char exp[] = "var res=something+long_id_starts_here_long_id_ends_here;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
}

TEST_CASE("split in keyword", "[JSNormalizer]")
{
    auto norm = default_config.derive({normalize_identifiers(false), use_expected_for_last_pdu(true)});

    SECTION("finally")
    {
        const char dat1[] = "\nfin";
        const char dat2[] = "ally;";
        const char exp1[] = "fin";
        const char exp2[] = "finally;";
        const char exp[] = "finally;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("in")
    {
        const char dat1[] = "i";
        const char dat2[] = "n";
        const char exp1[] = "i";
        const char exp2[] = "in";
        const char exp[] = "in";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("instanceof")
    {
        const char dat1[] = "in";
        const char dat2[] = "stance";
        const char dat3[] = "of";
        const char exp1[] = "in";
        const char exp2[] = "instance";
        const char exp3[] = "instanceof";
        const char exp[] = "instanceof";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
                {dat3, exp3},
            });

        norm.test_normalization_combined({dat1, dat2, dat3}, exp);
    }
}

TEST_CASE("split in integer literal", "[JSNormalizer]")
{
    auto norm = default_config.derive({normalize_identifiers(false), use_expected_for_last_pdu(true)});

    SECTION("1 2;")
    {
        const char dat1[] = "1";
        const char dat2[] = "2;";
        const char exp1[] = "1";
        const char exp2[] = "12;";
        const char exp[] = "12;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("0 b01;")
    {
        const char dat1[] = "0";
        const char dat2[] = "b01;";
        const char exp1[] = "0";
        const char exp2[] = "0b01;";
        const char exp[] = "0b01;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("0o 12;")
    {
        const char dat1[] = "0o";
        const char dat2[] = "12;";
        const char exp1[] = "0 o";
        const char exp2[] = "0o12;";
        const char exp[] = "0o12;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("0 12;")
    {
        const char dat1[] = "0";
        const char dat2[] = "12;";
        const char exp1[] = "0";
        const char exp2[] = "012;";
        const char exp[] = "012;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("01 9;")
    {
        const char dat1[] = "01";
        const char dat2[] = "9;";
        const char exp1[] = "01";
        const char exp2[] = "019;";
        const char exp[] = "019;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION(". 12;")
    {
        const char dat1[] = ".";
        const char dat2[] = "12;";
        const char exp1[] = ".";
        const char exp2[] = ".12;";
        const char exp[] = ".12;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("0 x 12;")
    {
        const char dat1[] = "0";
        const char dat2[] = "x";
        const char dat3[] = "12;";
        const char exp1[] = "0";
        const char exp2[] = " x";
        const char exp3[] = "0x12;";
        const char exp[] = "0x12;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
                {dat3, exp3},
            });

        norm.test_normalization_combined({dat1, dat2, dat3}, exp);
    }
    SECTION("1 _ 2;")
    {
        const char dat1[] = "1";
        const char dat2[] = "_";
        const char dat3[] = "2;";
        const char exp1[] = "1";
        const char exp2[] = " _";
        const char exp3[] = "1_2;";
        const char exp[] = "1_2;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
                {dat3, exp3},
            });

        norm.test_normalization_combined({dat1, dat2, dat3}, exp);
    }
    SECTION("1 E 2;")
    {
        const char dat1[] = "1";
        const char dat2[] = "E";
        const char dat3[] = "2;";
        const char exp1[] = "1";
        const char exp2[] = " E";
        const char exp3[] = "1E2;";
        const char exp[] = "1E2;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
                {dat3, exp3},
            });

        norm.test_normalization_combined({dat1, dat2, dat3}, exp);
    }
}

TEST_CASE("split and continuation combined", "[JSNormalizer]")
{
    SECTION("PDU 1 [cont] PDU 2 [end end cont end]")
    {
        const char src1[] = "a b"    "";
        const char src2[] = "c d"    "</script>";
        const char src3[] = ""       "</script>";
        const char src4[] = "\n"     "";

        const char exp1[] = "var_0000 var_0001";
        const char exp2[] = "var_0000 var_0002 var_0003";
        const char exp3[] = "var_0000 var_0002 var_0003";
        const char exp4[] = "var_0000 var_0002 var_0003";

        JSTokenizerTester tester(default_config);

        tester.do_pdu(src1);
        tester.check_output(exp1);

        tester.do_pdu(src2);
        tester.check_output(exp2);
        tester.run_checks({return_code(JSTokenizer::SCRIPT_ENDED)});

        tester.do_pdu(src3);
        tester.check_output(exp3);
        tester.run_checks({return_code(JSTokenizer::SCRIPT_ENDED)});

        tester.do_pdu(src4);
        tester.check_output(exp4);

        tester.do_pdu("</script>");
        tester.run_checks({return_code(JSTokenizer::SCRIPT_ENDED)});
    }

    SECTION("PDU 1 [cont] PDU 2 [cont] PDU 3 [end]")
    {
        const char src1[] = "<";
        const char src2[] = "!-";
        const char src3[] = "-comment\n";

        const char exp1[] = "<";
        const char exp2[] = "!-";
        const char exp3[] = "";

        std::string tmp_buf1 = "<";
        std::string tmp_buf2 = "<!-";
        std::string tmp_buf3 = "<!--comment\n";

        auto last_pdu_conf = default_config.derive({use_expected_for_last_pdu(true)});
        JSTokenizerTester tester(last_pdu_conf);

        tester.do_pdu(src1);
        tester.check_output(exp1);
        tester.run_checks(
            {
                return_code(JSTokenizer::SCRIPT_CONTINUE),
                temporary_buffer(tmp_buf1)
            });

        tester.do_pdu(src2);
        tester.check_output(exp2);
        tester.run_checks(
            {
                return_code(JSTokenizer::SCRIPT_CONTINUE),
                temporary_buffer(tmp_buf2)
            });

        tester.do_pdu(src3);
        tester.check_output(exp3);
        tester.run_checks(
            {
                return_code(JSTokenizer::SCRIPT_CONTINUE),
                temporary_buffer(tmp_buf3)
            });

        tester.do_pdu("</script>");
        tester.run_checks({return_code(JSTokenizer::SCRIPT_ENDED)});
    }
}

TEST_CASE("memcap", "[JSNormalizer]")
{
    auto norm = default_config.derive({normalize_identifiers(false), use_expected_for_last_pdu(true)});

    SECTION("3 tokens")
    {
        const char dat1[] = "var abc=in";
        const char dat2[] = "put;";
        const char exp1[] = "var abc=in";
        const char exp2[] = "input;";
        const char exp[] = "var abc=input;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            },
            {max_token_buf_size(6)});

        norm.test_normalization_combined({dat1, dat2}, exp,
            {max_token_buf_size(6)});
    }
    SECTION("2 tokens and a half")
    {
        const char dat1[] = "var abc=in";
        const char dat2[] = "put;";
        const char exp1[] = "var abc=in";
        const char exp2[] = "input;";
        const char exp[] = "var abc=input;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            },
            {max_token_buf_size(4)});

        norm.test_normalization_combined({dat1, dat2}, exp,
            {max_token_buf_size(4)});
    }
    SECTION("1 token")
    {
        const char dat1[] = "var abc=in";
        const char dat2[] = "put;";
        const char exp1[] = "var abc=in";
        const char exp2[] = "input;";
        const char exp[] = "var abc=input;";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            },
            {max_token_buf_size(2)});

        norm.test_normalization_combined({dat1, dat2}, exp,
            {max_token_buf_size(2)});
    }
    SECTION("a half")
    {
        const char dat1[] = "var abc=extract";
        const char dat2[] = "// just a comment\n";
        const char exp1[] = "var abc=extract";
        const char exp2[] = "";
        const char exp[] = "var abc=extract";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            },
            {max_token_buf_size(5)});

        norm.test_normalization_combined({dat1, dat2}, exp,
            {max_token_buf_size(5)});
    }
}

TEST_CASE("scope tracking", "[JSNormalizer]")
{
    auto norm = default_config.derive({normalize_identifiers(false), use_expected_for_last_pdu(true)});

    SECTION("parentheses")
    {
        const char dat1[] = "()";
        const char dat2[] = "()()()";
        const char dat3[] = "((()))";
        const char exp1[] = "()";
        const char exp2[] = "()()()";
        const char exp3[] = "((()))";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
    }
    SECTION("curly braces")
    {
        const char dat1[] = "{}";
        const char dat2[] = "{}{}{}";
        const char dat3[] = "{{{}}}";
        const char exp1[] = "{}";
        const char exp2[] = "{}{}{}";
        const char exp3[] = "{{{}}}";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
    }
    SECTION("square brackets")
    {
        const char dat1[] = "[]";
        const char dat2[] = "[][][]";
        const char dat3[] = "[[[]]]";
        const char exp1[] = "[]";
        const char exp2[] = "[][][]";
        const char exp3[] = "[[[]]]";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
    }
    SECTION("mix of brackets")
    {
        const char dat1[] = "(){}[]";
        const char dat2[] = "({})[]";
        const char dat3[] = "(){[]}";
        const char exp1[] = "(){}[]";
        const char exp2[] = "({})[]";
        const char exp3[] = "(){[]}";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
    }
    SECTION("parentheses - wrong closing symbol")
    {
        const char dat1[] = "({[ (} ]})";
        const char dat2[] = "({[ (] ]})";
        const char exp1[] = "({[(";
        const char exp2[] = "({[(";

        test_normalization(dat1, exp1, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        test_normalization(dat2, exp2, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
    }
    SECTION("curly braces - wrong closing symbol")
    {
        const char dat1[] = "({[ {) ]})";
        const char dat2[] = "({[ {] ]})";
        const char exp1[] = "({[{";
        const char exp2[] = "({[{";

        test_normalization(dat1, exp1, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        test_normalization(dat2, exp2, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
    }
    SECTION("square brackets - wrong closing symbol")
    {
        const char dat1[] = "([{ [) }])";
        const char dat2[] = "([{ [} }])";
        const char exp1[] = "([{[";
        const char exp2[] = "([{[";

        test_normalization(dat1, exp1, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        test_normalization(dat2, exp2, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
    }
    SECTION("parentheses - mismatch")
    {
        const char dat1[] = ")";
        const char dat2[] = "())";
        const char dat3[] = "({[ ()) ]})";
        const char dat4[] = "(</script>";
        const char dat5[] = "(()</script>";
        const char exp1[] = "";
        const char exp2[] = "()";
        const char exp3[] = "({[()";
        const char exp4[] = "(";
        const char exp5[] = "(()";

        test_normalization(dat1, exp1, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        test_normalization(dat2, exp2, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        test_normalization(dat3, exp3, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        test_normalization(dat4, exp4, {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)});
        test_normalization(dat5, exp5, {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)});
    }
    SECTION("curly braces - mismatch")
    {
        const char dat1[] = "}";
        const char dat2[] = "{}}";
        const char dat3[] = "({[ {}} ]})";
        const char dat4[] = "{</script>";
        const char dat5[] = "{{}</script>";
        const char exp1[] = "";
        const char exp2[] = "{}";
        const char exp3[] = "({[{}";
        const char exp4[] = "{";
        const char exp5[] = "{{}";

        test_normalization(dat1, exp1, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        test_normalization(dat2, exp2, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        test_normalization(dat3, exp3, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        test_normalization(dat4, exp4, {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)});
        test_normalization(dat5, exp5, {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)});
    }
    SECTION("square brackets - mismatch")
    {
        const char dat1[] = "]";
        const char dat2[] = "[]]";
        const char dat3[] = "([{ []] }])";
        const char dat4[] = "[</script>";
        const char dat5[] = "[[]</script>";
        const char exp1[] = "";
        const char exp2[] = "[]";
        const char exp3[] = "([{[]";
        const char exp4[] = "[";
        const char exp5[] = "[[]";

        test_normalization(dat1, exp1, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        test_normalization(dat2, exp2, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        test_normalization(dat3, exp3, {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        test_normalization(dat4, exp4, {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)});
        test_normalization(dat5, exp5, {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)});
    }
    SECTION("parentheses - continuation")
    {
        const char dat1[] = "((";
        const char dat2[] = "))";
        const char exp1[] = "((";
        const char exp2[] = "))";
        const char exp[] = "(())";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("curly braces - continuation")
    {
        const char dat1[] = "{{";
        const char dat2[] = "}}";
        const char exp1[] = "{{";
        const char exp2[] = "}}";
        const char exp[] = "{{}}";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("square brackets - continuation")
    {
        const char dat1[] = "[[";
        const char dat2[] = "]]";
        const char exp1[] = "[[";
        const char exp2[] = "]]";
        const char exp[] = "[[]]";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("parentheses - mismatch in continuation")
    {
        const char dat1[] = "(";
        const char dat2[] = "))";
        const char dat3[] = "(";
        const char dat4[] = " </script>";
        const char exp1[] = "(";
        const char exp2[] = ")";
        const char exp3[] = "(";
        const char exp4[] = "";

        const char exp5[] = "()";
        const char exp6[] = "(";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            },
            {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});

        norm.test_normalization(
            {
                {dat3, exp3},
                {dat4, exp4},
            },
            {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)});


        norm.test_normalization_combined({dat1, dat2}, exp5,
            {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        norm.test_normalization_combined({dat3, dat4}, exp6,
            {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)});
    }
    SECTION("curly braces - mismatch in continuation")
    {
        const char dat1[] = "{";
        const char dat2[] = "}}";
        const char dat3[] = "{";
        const char dat4[] = " </script>";
        const char exp1[] = "{";
        const char exp2[] = "}";
        const char exp3[] = "{";
        const char exp4[] = "";

        const char exp5[] = "{}";
        const char exp6[] = "{";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            },
            {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});

        norm.test_normalization(
            {
                {dat3, exp3},
                {dat4, exp4},
            },
            {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)});


        norm.test_normalization_combined({dat1, dat2}, exp5,
            {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        norm.test_normalization_combined({dat3, dat4}, exp6,
            {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)});
    }
    SECTION("square brackets - mismatch in continuation")
    {
        const char dat1[] = "[";
        const char dat2[] = "]]";
        const char dat3[] = "[";
        const char dat4[] = " </script>";
        const char exp1[] = "[";
        const char exp2[] = "]";
        const char exp3[] = "[";
        const char exp4[] = "";

        const char exp5[] = "[]";
        const char exp6[] = "[";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            },
            {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});

        norm.test_normalization(
            {
                {dat3, exp3},
                {dat4, exp4},
            },
            {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)});


        norm.test_normalization_combined({dat1, dat2}, exp5,
            {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        norm.test_normalization_combined({dat3, dat4}, exp6,
            {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)});
    }
}

TEST_CASE("scope misc", "[JSNormalizer]")
{
    const int stack_limit = 256;
    const char* open = "1+(";
    const char* close = "-1)";

    SECTION("one below max stack")
    {
        std::string scr;

        for (int i = 0; i < stack_limit - 1; ++i)
            scr += open;
        for (int i = 0; i < stack_limit - 1; ++i)
            scr += close;

        test_normalization(scr, scr, {return_code(JSTokenizer::SCRIPT_CONTINUE)});
    }

    SECTION("over max stack")
    {
        std::string scr;
        std::string nsc;

        for (int i = 0; i < stack_limit; ++i)
            scr += open;
        for (int i = 0; i < stack_limit; ++i)
            scr += close;
        for (int i = 0; i < stack_limit - 1; ++i)
            nsc += open;
        nsc += "1+";

        test_normalization(scr, nsc, {return_code(JSTokenizer::BRACKET_NESTING_OVERFLOW)});
    }
}

TEST_CASE("scope tail handling", "[JSNormalizer]")
{
    auto norm = default_config.derive({normalize_identifiers(false), use_expected_for_last_pdu(true)});
    // Padding ':' symbol has been chosen, since it:
    //  * forms a single state for Parser
    //  * doesn't insert white spaces
    //  * forms a single match, i.e. there are no '::' ':::' patterns
    //
    // Thus, the tail of "::({[]})" will have JSTOKENIZER_MAX_STATES
    // and the same number of characters in it.

#if JSTOKENIZER_MAX_STATES != 8
#error "scope tail handling" tests are designed for the tail of 8 bytes size
#endif

    SECTION("no scope-symbols in the tail")
    {
        const char dat1[] = "((((::::::::";
        const char dat2[] = "):):):):";
        const char dat3[] = "{}{{::::::::";
        const char dat4[] = "::{}}}::";
        const char dat5[] = "[][[::::::::";
        const char dat6[] = "::::]][]";
        const char exp1[] = "((((::::::::";
        const char exp2[] = "):):):):";
        const char exp3[] = "{}{{::::::::";
        const char exp4[] = "::{}}}::";
        const char exp5[] = "[][[::::::::";
        const char exp6[] = "::::]][]";

        const char exp7[] = "((((::::::::):):):):";
        const char exp8[] = "{}{{::::::::::{}}}::";
        const char exp9[] = "[][[::::::::::::]][]";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization(
            {
                {dat3, exp3},
                {dat4, exp4},
            });

        norm.test_normalization(
            {
                {dat5, exp5},
                {dat6, exp6},
            });


        norm.test_normalization_combined({dat1, dat2}, exp7);
        norm.test_normalization_combined({dat3, dat4}, exp8);
        norm.test_normalization_combined({dat5, dat6}, exp9);
    }

    SECTION("opening scope-symbols in the tail")
    {
        const char dat1[] = "::::(:::::::";
        const char dat2[] = "):::::::";
        const char dat3[] = ":::::::::::{";
        const char dat4[] = ":::::::}";
        const char dat5[] = "::::[:::::::";
        const char dat6[] = "::::]:::";
        const char exp1[] = "::::(:::::::";
        const char exp2[] = "):::::::";
        const char exp3[] = ":::::::::::{";
        const char exp4[] = ":::::::}";
        const char exp5[] = "::::[:::::::";
        const char exp6[] = "::::]:::";

        const char exp7[] = "::::(:::::::):::::::";
        const char exp8[] = ":::::::::::{:::::::}";
        const char exp9[] = "::::[:::::::::::]:::";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization(
            {
                {dat3, exp3},
                {dat4, exp4},
            });

        norm.test_normalization(
            {
                {dat5, exp5},
                {dat6, exp6},
            });


        norm.test_normalization_combined({dat1, dat2}, exp7);
        norm.test_normalization_combined({dat3, dat4}, exp8);
        norm.test_normalization_combined({dat5, dat6}, exp9);
    }

    SECTION("closing scope-symbols in the tail")
    {
        const char dat1[] = "(((()::::::)";
        const char dat2[] = "()::::))";
        const char dat3[] = "{{{{:::::::}";
        const char dat4[] = ":::::}}}";
        const char dat5[] = "[::::::::]::";
        const char dat6[] = "::::::::";
        const char exp1[] = "(((()::::::)";
        const char exp2[] = "()::::))";
        const char exp3[] = "{{{{:::::::}";
        const char exp4[] = ":::::}}}";
        const char exp5[] = "[::::::::]::";
        const char exp6[] = "::::::::";

        const char exp7[] = "(((()::::::)()::::))";
        const char exp8[] = "{{{{:::::::}:::::}}}";
        const char exp9[] = "[::::::::]::::::::::";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization(
            {
                {dat3, exp3},
                {dat4, exp4},
            });

        norm.test_normalization(
            {
                {dat5, exp5},
                {dat6, exp6},
            });


        norm.test_normalization_combined({dat1, dat2}, exp7);
        norm.test_normalization_combined({dat3, dat4}, exp8);
        norm.test_normalization_combined({dat5, dat6}, exp9);
    }

    SECTION("newly opening scope-symbols in the tail")
    {
        const char dat1[] = "(:::(::::::(";
        const char dat2[] = "))):::::";
        const char dat3[] = "{:{:{:{:{:{:";
        const char dat4[] = "::}}}}}}";
        const char dat5[] = "[:[:[:::[:::";
        const char dat6[] = "::::]]]]";
        const char exp1[] = "(:::(::::::(";
        const char exp2[] = "))):::::";
        const char exp3[] = "{:{:{:{:{:{:";
        const char exp4[] = "::}}}}}}";
        const char exp5[] = "[:[:[:::[:::";
        const char exp6[] = "::::]]]]";

        const char exp7[] = "(:::(::::::())):::::";
        const char exp8[] = "{:{:{:{:{:{:::}}}}}}";
        const char exp9[] = "[:[:[:::[:::::::]]]]";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization(
            {
                {dat3, exp3},
                {dat4, exp4},
            });

        norm.test_normalization(
            {
                {dat5, exp5},
                {dat6, exp6},
            });


        norm.test_normalization_combined({dat1, dat2}, exp7);
        norm.test_normalization_combined({dat3, dat4}, exp8);
        norm.test_normalization_combined({dat5, dat6}, exp9);
    }

    SECTION("fully closing scope-symbols in the tail")
    {
        const char dat1[] = "((((::::))))";
        const char dat2[] = "::::::::";
        const char dat3[] = "{{{{}:}:}:}:";
        const char dat4[] = "::::{}{}";
        const char dat5[] = "[[:::::::]:]";
        const char dat6[] = "[::::::]";
        const char exp1[] = "((((::::))))";
        const char exp2[] = "::::::::";
        const char exp3[] = "{{{{}:}:}:}:";
        const char exp4[] = "::::{}{}";
        const char exp5[] = "[[:::::::]:]";
        const char exp6[] = "[::::::]";

        const char exp7[] = "((((::::))))::::::::";
        const char exp8[] = "{{{{}:}:}:}:::::{}{}";
        const char exp9[] = "[[:::::::]:][::::::]";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization(
            {
                {dat3, exp3},
                {dat4, exp4},
            });

        norm.test_normalization(
            {
                {dat5, exp5},
                {dat6, exp6},
            });


        norm.test_normalization_combined({dat1, dat2}, exp7);
        norm.test_normalization_combined({dat3, dat4}, exp8);
        norm.test_normalization_combined({dat5, dat6}, exp9);
    }

    SECTION("extra scope-symbols in the tail")
    {
        const char dat1[] = "((((((((";
        const char dat2[] = ")))))))))";
        const char dat3[] = "{{{{{{{{";
        const char dat4[] = "}}}}}}]}";
        const char dat5[] = "[[[[[[[[";
        const char dat6[] = "]]]]]]]</script>";
        const char exp1[] = "((((((((";
        const char exp2[] = "))))))))";
        const char exp3[] = "{{{{{{{{";
        const char exp4[] = "}}}}}}";
        const char exp5[] = "[[[[[[[[";
        const char exp6[] = "]]]]]]]";

        const char exp7[] = "(((((((())))))))";
        const char exp8[] = "{{{{{{{{}}}}}}";
        const char exp9[] = "[[[[[[[[]]]]]]]";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            },
            {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});

        norm.test_normalization(
            {
                {dat3, exp3},
                {dat4, exp4},
            },
            {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});

        norm.test_normalization(
            {
                {dat5, exp5},
                {dat6, exp6},
            },
            {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)});


        norm.test_normalization_combined({dat1, dat2}, exp7,
            {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        norm.test_normalization_combined({dat3, dat4}, exp8,
            {return_code(JSTokenizer::WRONG_CLOSING_SYMBOL)});
        norm.test_normalization_combined({dat5, dat6}, exp9,
            {return_code(JSTokenizer::ENDED_IN_INNER_SCOPE)});
    }

    SECTION("overwriting scope-symbols in the tail")
    {
        const char dat1[] = "(((((((())))";
        const char dat2[] = ":))))";
        const char dat3[] = "({[(:):]{}{}";
        const char dat4[] = "}[]())";
        const char dat5[] = "{{{{}[[]](((";
        const char dat6[] = ")))}}}";
        const char exp1[] = "(((((((())))";
        const char exp2[] = ":))))";
        const char exp3[] = "({[(:):]{}{}";
        const char exp4[] = "}[]())";
        const char exp5[] = "{{{{}[[]](((";
        const char exp6[] = ")))}}}";

        const char exp7[] = "(((((((()))):))))";
        const char exp8[] = "({[(:):]{}{}}[]())";
        const char exp9[] = "{{{{}[[]]((()))}}}";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization(
            {
                {dat3, exp3},
                {dat4, exp4},
            });

        norm.test_normalization(
            {
                {dat5, exp5},
                {dat6, exp6},
            });


        norm.test_normalization_combined({dat1, dat2}, exp7);
        norm.test_normalization_combined({dat3, dat4}, exp8);
        norm.test_normalization_combined({dat5, dat6}, exp9);
    }
}

TEST_CASE("scope regex groups", "[JSNormalizer]")
{
    auto norm = default_config.derive({normalize_identifiers(false), use_expected_for_last_pdu(true)});

    SECTION("parentheses")
    {
        const char dat1[] = "a=/()/;";
        const char dat2[] = "b=/()()()/;";
        const char dat3[] = "c=/((()))/;";
        const char exp1[] = "a=/()/;";
        const char exp2[] = "b=/()()()/;";
        const char exp3[] = "c=/((()))/;";

        test_normalization_noident(dat1, exp1);
        test_normalization_noident(dat2, exp2);
        test_normalization_noident(dat3, exp3);
    }
    SECTION("curly braces")
    {
        const char dat1[] = "a=/{}/;";
        const char dat2[] = "b=/{}{}{}/;";
        const char dat3[] = "c=/{{{}}}/;";
        const char exp1[] = "a=/{}/;";
        const char exp2[] = "b=/{}{}{}/;";
        const char exp3[] = "c=/{{{}}}/;";

        test_normalization_noident(dat1, exp1);
        test_normalization_noident(dat2, exp2);
        test_normalization_noident(dat3, exp3);
    }
    SECTION("square brackets")
    {
        const char dat1[] = "a=/[]/;";
        const char dat2[] = "b=/[][][]/;";
        const char dat3[] = "c=/[[[[[]/;";
        const char dat4[] = "d=/[/]/;";
        const char exp1[] = "a=/[]/;";
        const char exp2[] = "b=/[][][]/;";
        const char exp3[] = "c=/[[[[[]/;";
        const char exp4[] = "d=/[/]/;";

        test_normalization_noident(dat1, exp1);
        test_normalization_noident(dat2, exp2);
        test_normalization_noident(dat3, exp3);
        test_normalization_noident(dat4, exp4);
    }
    SECTION("mix of brackets")
    {
        const char dat1[] = "a=/(){}[]/";
        const char dat2[] = "b=/({})[]/";
        const char dat3[] = "c=/(){[]}/";
        const char exp1[] = "a=/(){}[]/";
        const char exp2[] = "b=/({})[]/";
        const char exp3[] = "c=/(){[]}/";

        test_normalization_noident(dat1, exp1);
        test_normalization_noident(dat2, exp2);
        test_normalization_noident(dat3, exp3);
    }
    SECTION("square brackets - raw bracket")
    {
        const char dat1[] = "/]/";
        const char dat2[] = "/[]]/";
        const char dat3[] = "/][]]/g";
        const char exp1[] = "/]/";
        const char exp2[] = "/[]]/";
        const char exp3[] = "/][]]/g";

        test_normalization_noident(dat1, exp1);
        test_normalization_noident(dat2, exp2);
        test_normalization_noident(dat3, exp3);
    }
    SECTION("parentheses - mismatch")
    {
        const char dat1[] = "/)/";
        const char dat2[] = "/())/";
        const char dat3[] = "/( ()) )/";
        const char exp1[] = "/";
        const char exp2[] = "/()";
        const char exp3[] = "/( ()) ";

        test_normalization(dat1, exp1, {return_code(JSTokenizer::BAD_TOKEN)});
        test_normalization(dat2, exp2, {return_code(JSTokenizer::BAD_TOKEN)});
        test_normalization(dat3, exp3, {return_code(JSTokenizer::BAD_TOKEN)});
    }
    SECTION("parentheses - continuation")
    {
        const char dat1[] = "/((";
        const char dat2[] = "))/";
        const char exp1[] = "/((";
        const char exp2[] = "))/";
        const char exp[] = "/(())/";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("square brackets - continuation")
    {
        const char dat1[] = "/[[";
        const char dat2[] = "[]/";
        const char exp1[] = "/[[";
        const char exp2[] = "[]/";
        const char exp[] = "/[[[]/";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            });

        norm.test_normalization_combined({dat1, dat2}, exp);
    }
    SECTION("parentheses - mismatch in continuation")
    {
        const char dat1[] = "/(";
        const char dat2[] = "))/";
        const char exp1[] = "/(";
        const char exp2[] = ")";
        const char exp[] = "/()";

        norm.test_normalization(
            {
                {dat1, exp1},
                {dat2, exp2},
            },
            {return_code(JSTokenizer::BAD_TOKEN)});

        norm.test_normalization_combined({dat1, dat2}, exp,
            {return_code(JSTokenizer::BAD_TOKEN)});
    }
}

TEST_CASE("ignored identifiers", "[JSNormalizer]")
{
    // 'console' 'eval' 'document' are in the ignore list

    SECTION("a standalone identifier")
    {
        const char dat1[] = "alpha bravo console delta eval";
        const char dat2[] = "var a = 0;     console = 1;";
        const char dat3[] = "var a = 0; var console = 1;";
        const char dat4[] = "foo(0); console(1); bar(2); console1(3); baz(4);";
        const char dat5[] = "foo(0);    eval(1); bar(2); evaluate(3); baz(4);";
        const char exp1[] = "var_0000 var_0001 console var_0002 eval";
        const char exp2[] = "var var_0000=0;console=1;";
        const char exp3[] = "var var_0000=0;var console=1;";
        const char exp4[] = "var_0000(0);console(1);var_0001(2);var_0002(3);var_0003(4);";
        const char exp5[] = "var_0000(0);eval(1);var_0001(2);var_0002(3);var_0003(4);";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);
        test_normalization(dat5, exp5);
    }

    SECTION("inner objects")
    {
        const char dat1[] = "alpha.bravo.charlie.delta";
        const char dat2[] = "alpha.bravo.console.delta";
        const char dat3[] = "eval.alpha.bravo.charlie.delta";
        const char dat4[] = "eval.alpha.bravo.console.delta";
        const char exp1[] = "var_0000.var_0001.var_0002.var_0003";
        const char exp2[] = "var_0000.var_0001.var_0002.var_0003";
        const char exp3[] = "eval.alpha.bravo.charlie.delta";
        const char exp4[] = "eval.alpha.bravo.console.delta";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);
    }

    SECTION("function calls")
    {
        const char dat1[] = "foo.bar.baz()";
        const char dat2[] = "foo.bar().baz";
        const char dat3[] = "foo().bar.baz";
        const char dat4[] = "eval.bar.baz()";
        const char dat5[] = "eval.bar().baz";
        const char dat6[] = "eval().bar.baz";
        const char dat7[] = "foo.eval.baz()";
        const char dat8[] = "foo.eval().baz";
        const char dat9[] = "foo().eval.baz";
        const char dat10[] = "foo.bar.eval()";
        const char dat11[] = "foo.bar().eval";
        const char dat12[] = "var_0000().bar.eval";
        const char exp1[] = "var_0000.var_0001.var_0002()";
        const char exp2[] = "var_0000.var_0001().var_0002";
        const char exp3[] = "var_0000().var_0001.var_0002";
        const char exp4[] = "eval.bar.baz()";
        const char exp5[] = "eval.bar().baz";
        const char exp6[] = "eval().bar.baz";
        const char exp7[] = "var_0000.var_0001.var_0002()";
        const char exp8[] = "var_0000.var_0001().var_0002";
        const char exp9[] = "var_0000().var_0001.var_0002";
        const char exp10[] = "var_0000.var_0001.var_0002()";
        const char exp11[] = "var_0000.var_0001().var_0002";
        const char exp12[] = "var_0000().var_0001.var_0002";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);
        test_normalization(dat5, exp5);
        test_normalization(dat6, exp6);
        test_normalization(dat7, exp7);
        test_normalization(dat8, exp8);
        test_normalization(dat9, exp9);
        test_normalization(dat10, exp10);
        test_normalization(dat11, exp11);
        test_normalization(dat12, exp12);
    }
}

TEST_CASE("ignored identifier chain tracking", "[JSNormalizer]")
{
    // 'console' 'eval' 'document' are in the ignore list

    SECTION("chain terminators")
    {
        const char dat1[] = "eval.foo.bar.baz";
        const char dat2[] = "eval.foo bar.baz";
        const char dat3[] = "eval.foo;bar.baz";
        const char dat4[] = "eval.foo,bar.baz";
        const char dat5[] = "eval.foo*bar.baz";
        const char dat6[] = "eval.foo*=bar.baz";
        const char dat7[] = "eval.foo/bar.baz";
        const char dat8[] = "eval.foo/=bar.baz";
        const char dat9[] = "eval.foo%bar.baz";
        const char dat10[] = "eval.foo%=bar.baz";
        const char dat11[] = "eval.foo+bar.baz";
        const char dat12[] = "eval.foo+=bar.baz";
        const char dat13[] = "eval.foo-bar.baz";
        const char dat14[] = "eval.foo-=bar.baz";
        const char dat15[] = "eval.foo<<bar.baz";
        const char dat16[] = "eval.foo<<=bar.baz";
        const char dat17[] = "eval.foo>>bar.baz";
        const char dat18[] = "eval.foo>>=bar.baz";
        const char dat19[] = "eval.foo>>>bar.baz";
        const char dat20[] = "eval.foo>>>=bar.baz";
        const char dat21[] = "eval.foo<bar.baz";
        const char dat22[] = "eval.foo<=bar.baz";
        const char dat23[] = "eval.foo>bar.baz";
        const char dat24[] = "eval.foo>=bar.baz";
        const char dat25[] = "eval.foo instanceof bar.baz";
        const char dat26[] = "eval.foo==bar.baz";
        const char dat27[] = "eval.foo!=bar.baz";
        const char dat28[] = "eval.foo===bar.baz";
        const char dat29[] = "eval.foo!==bar.baz";
        const char dat30[] = "eval.foo&bar.baz";
        const char dat31[] = "eval.foo&=bar.baz";
        const char dat32[] = "eval.foo&&bar.baz";
        const char dat33[] = "eval.foo|bar.baz";
        const char dat34[] = "eval.foo|=bar.baz";
        const char dat35[] = "eval.foo||bar.baz";
        const char dat36[] = "eval.foo^bar.baz";
        const char dat37[] = "eval.foo^=bar.baz";
        const char dat38[] = "eval.foo?bar.baz";
        const char dat39[] = "eval.foo(bar.baz)";
        const char dat40[] = "eval.var.foo";
        const char dat41[] = "eval. break() . foo";

        const char exp1[] = "eval.foo.bar.baz";
        const char exp2[] = "eval.foo var_0000.var_0001";
        const char exp3[] = "eval.foo;var_0000.var_0001";
        const char exp4[] = "eval.foo,var_0000.var_0001";
        const char exp5[] = "eval.foo*var_0000.var_0001";
        const char exp6[] = "eval.foo*=var_0000.var_0001";
        const char exp7[] = "eval.foo/var_0000.var_0001";
        const char exp8[] = "eval.foo/=var_0000.var_0001";
        const char exp9[] = "eval.foo%var_0000.var_0001";
        const char exp10[] = "eval.foo%=var_0000.var_0001";
        const char exp11[] = "eval.foo+var_0000.var_0001";
        const char exp12[] = "eval.foo+=var_0000.var_0001";
        const char exp13[] = "eval.foo-var_0000.var_0001";
        const char exp14[] = "eval.foo-=var_0000.var_0001";
        const char exp15[] = "eval.foo<<var_0000.var_0001";
        const char exp16[] = "eval.foo<<=var_0000.var_0001";
        const char exp17[] = "eval.foo>>var_0000.var_0001";
        const char exp18[] = "eval.foo>>=var_0000.var_0001";
        const char exp19[] = "eval.foo>>>var_0000.var_0001";
        const char exp20[] = "eval.foo>>>=var_0000.var_0001";
        const char exp21[] = "eval.foo<var_0000.var_0001";
        const char exp22[] = "eval.foo<=var_0000.var_0001";
        const char exp23[] = "eval.foo>var_0000.var_0001";
        const char exp24[] = "eval.foo>=var_0000.var_0001";
        const char exp25[] = "eval.foo instanceof var_0000.var_0001";
        const char exp26[] = "eval.foo==var_0000.var_0001";
        const char exp27[] = "eval.foo!=var_0000.var_0001";
        const char exp28[] = "eval.foo===var_0000.var_0001";
        const char exp29[] = "eval.foo!==var_0000.var_0001";
        const char exp30[] = "eval.foo&var_0000.var_0001";
        const char exp31[] = "eval.foo&=var_0000.var_0001";
        const char exp32[] = "eval.foo&&var_0000.var_0001";
        const char exp33[] = "eval.foo|var_0000.var_0001";
        const char exp34[] = "eval.foo|=var_0000.var_0001";
        const char exp35[] = "eval.foo||var_0000.var_0001";
        const char exp36[] = "eval.foo^var_0000.var_0001";
        const char exp37[] = "eval.foo^=var_0000.var_0001";
        const char exp38[] = "eval.foo?var_0000.var_0001";
        const char exp39[] = "eval.foo(var_0000.var_0001)";
        const char exp40[] = "eval.var.foo";
        const char exp41[] = "eval.break().foo";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);
        test_normalization(dat5, exp5);
        test_normalization(dat6, exp6);
        test_normalization(dat7, exp7);
        test_normalization(dat8, exp8);
        test_normalization(dat9, exp9);
        test_normalization(dat10, exp10);
        test_normalization(dat11, exp11);
        test_normalization(dat12, exp12);
        test_normalization(dat13, exp13);
        test_normalization(dat14, exp14);
        test_normalization(dat15, exp15);
        test_normalization(dat16, exp16);
        test_normalization(dat17, exp17);
        test_normalization(dat18, exp18);
        test_normalization(dat19, exp19);
        test_normalization(dat20, exp20);
        test_normalization(dat21, exp21);
        test_normalization(dat22, exp22);
        test_normalization(dat23, exp23);
        test_normalization(dat24, exp24);
        test_normalization(dat25, exp25);
        test_normalization(dat26, exp26);
        test_normalization(dat27, exp27);
        test_normalization(dat28, exp28);
        test_normalization(dat29, exp29);
        test_normalization(dat30, exp30);
        test_normalization(dat31, exp31);
        test_normalization(dat32, exp32);
        test_normalization(dat33, exp33);
        test_normalization(dat34, exp34);
        test_normalization(dat35, exp35);
        test_normalization(dat36, exp36);
        test_normalization(dat37, exp37);
        test_normalization(dat38, exp38);
        test_normalization(dat39, exp39);
        test_normalization(dat40, exp40);
        test_normalization(dat41, exp41);
    }

    SECTION("over inner scopes")
    {
        const char dat1[] = "eval.foo.bar.baz";
        const char dat2[] = "eval().foo.bar.baz";
        const char dat3[] = "eval.foo().bar.baz";
        const char dat4[] = "eval(foo.bar).baz";
        const char dat5[] = "eval.foo().bar[].baz";
        const char dat6[] = "eval.foo{bar[]}.baz";
        const char dat7[] = "eval(foo+bar).baz";
        const char dat8[] = "eval(foo bar).baz";
        const char exp1[] = "eval.foo.bar.baz";
        const char exp2[] = "eval().foo.bar.baz";
        const char exp3[] = "eval.foo().bar.baz";
        const char exp4[] = "eval(var_0000.var_0001).baz";
        const char exp5[] = "eval.foo().bar[].baz";
        const char exp6[] = "eval.foo{var_0000[]}.var_0001";
        const char exp7[] = "eval(var_0000+var_0001).baz";
        const char exp8[] = "eval(var_0000 var_0001).baz";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);
        test_normalization(dat5, exp5);
        test_normalization(dat6, exp6);
        test_normalization(dat7, exp7);
        test_normalization(dat8, exp8);
    }

    SECTION("spaces and operators")
    {
        const char dat1[] = "foo.bar.baz console.log";
        const char dat2[] = "console.log foo.bar.baz";
        const char dat3[] = "foo . bar . baz console . log";
        const char dat4[] = "console . log foo . bar . baz";
        const char dat5[] = "console . foo . bar . baz";
        const char dat6[] = "console = foo . bar . baz";
        const char dat7[] = "console . foo + bar . baz";
        const char dat8[] = "console . foo . bar : baz";
        const char dat9[] = "console.\nfoo";
        const char exp1[] = "var_0000.var_0001.var_0002 console.log";
        const char exp2[] = "console.log var_0000.var_0001.var_0002";
        const char exp3[] = "var_0000.var_0001.var_0002 console.log";
        const char exp4[] = "console.log var_0000.var_0001.var_0002";
        const char exp5[] = "console.foo.bar.baz";
        const char exp6[] = "console=var_0000.var_0001.var_0002";
        const char exp7[] = "console.foo+var_0000.var_0001";
        const char exp8[] = "console.foo.bar:var_0000";
        const char exp9[] = "console.foo";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);
        test_normalization(dat5, exp5);
        test_normalization(dat6, exp6);
        test_normalization(dat7, exp7);
        test_normalization(dat8, exp8);
        test_normalization(dat9, exp9);
    }

    SECTION("comments")
    {
        const char dat1[] = "console.<!-- HTML comment\nlog(abc).foo";
        const char dat2[] = "console.//single-line comment\nlog(abc).foo";
        const char dat3[] = "console./*multi-line comment*/log(abc).foo";
        const char exp[] = "console.log(var_0000).foo";

        test_normalization(dat1, exp);
        test_normalization(dat2, exp);
        test_normalization(dat3, exp);
    }
}

TEST_CASE("ignored identifier scope tracking", "[JSNormalizer]")
{
    // 'console' 'eval' 'document' are in the ignore list

    SECTION("basic")
    {
        const char dat1[] = "(alpha) bravo console delta eval foxtrot";
        const char dat2[] = "(alpha bravo) console delta eval foxtrot";
        const char dat3[] = "(alpha bravo console) delta eval foxtrot";
        const char dat4[] = "(alpha bravo console delta) eval foxtrot";
        const char dat5[] = "(alpha bravo console delta eval) foxtrot";
        const char dat6[] = "(alpha bravo console delta eval foxtrot)";
        const char dat7[] = "alpha bravo (console) delta (eval) foxtrot";
        const char exp1[] = "(var_0000)var_0001 console var_0002 eval var_0003";
        const char exp2[] = "(var_0000 var_0001)console var_0002 eval var_0003";
        const char exp3[] = "(var_0000 var_0001 console)var_0002 eval var_0003";
        const char exp4[] = "(var_0000 var_0001 console var_0002)eval var_0003";
        const char exp5[] = "(var_0000 var_0001 console var_0002 eval)var_0003";
        const char exp6[] = "(var_0000 var_0001 console var_0002 eval var_0003)";
        const char exp7[] = "var_0000 var_0001(console)var_0002(eval)var_0003";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);
        test_normalization(dat5, exp5);
        test_normalization(dat6, exp6);
        test_normalization(dat7, exp7);
    }

    SECTION("function calls")
    {
        const char dat1[] = "foo(bar).baz";
        const char dat2[] = "foo(bar(baz))";
        const char dat3[] = "eval(bar).baz";
        const char dat4[] = "eval(bar(baz))";
        const char dat5[] = "foo(eval).baz";
        const char dat6[] = "foo(eval(baz))";
        const char dat7[] = "foo(bar).eval";
        const char dat8[] = "foo(bar(eval))";
        const char dat9[] = "(console).log";
        const char dat10[] = "((console)).log";
        const char dat11[] = "((foo, console)).log";
        const char dat12[] = "((document.foo(bar), console)).log";
        const char dat13[] = "((document.foo(bar) console)).log";
        const char dat14[] = "((document.foo(bar) console))log";
        const char dat15[] = "((document.foo(bar) baz))log";
        const char dat16[] = "foo(console).log";
        const char dat17[] = "foo((console).log).log";
        const char dat18[] = "foo().baz + eval(eval['content'].bar + baz(console['content'].log, baz)).bar";
        const char dat19[] = "eval['foo']().bar.baz";
        const char dat20[] = "eval['foo']()['bar'].baz";
        const char dat21[] = "eval['foo']['bar'].baz()";
        const char exp1[] = "var_0000(var_0001).var_0002";
        const char exp2[] = "var_0000(var_0001(var_0002))";
        const char exp3[] = "eval(var_0000).baz";
        const char exp4[] = "eval(var_0000(var_0001))";
        const char exp5[] = "var_0000(eval).var_0001";
        const char exp6[] = "var_0000(eval(var_0001))";
        const char exp7[] = "var_0000(var_0001).var_0002";
        const char exp8[] = "var_0000(var_0001(eval))";
        const char exp9[] = "(console).log";
        const char exp10[] = "((console)).log";
        const char exp11[] = "((var_0000,console)).log";
        const char exp12[] = "((document.foo(var_0000),console)).log";
        const char exp13[] = "((document.foo(var_0000)console)).log";
        const char exp14[] = "((document.foo(var_0000)console))var_0001";
        const char exp15[] = "((document.foo(var_0000)var_0001))var_0002";
        const char exp16[] = "var_0000(console).var_0001";
        const char exp17[] = "var_0000((console).log).var_0001";
        const char exp18[] = "var_0000().var_0001+eval(eval['content'].bar+var_0001(console['content'].log,var_0001)).bar";
        const char exp19[] = "eval['foo']().bar.baz";
        const char exp20[] = "eval['foo']()['bar'].baz";
        const char exp21[] = "eval['foo']['bar'].baz()";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);
        test_normalization(dat5, exp5);
        test_normalization(dat6, exp6);
        test_normalization(dat7, exp7);
        test_normalization(dat8, exp8);
        test_normalization(dat9, exp9);
        test_normalization(dat10, exp10);
        test_normalization(dat11, exp11);
        test_normalization(dat12, exp12);
        test_normalization(dat13, exp13);
        test_normalization(dat14, exp14);
        test_normalization(dat15, exp15);
        test_normalization(dat16, exp16);
        test_normalization(dat17, exp17);
        test_normalization(dat18, exp18);
        test_normalization(dat19, exp19);
        test_normalization(dat20, exp20);
        test_normalization(dat21, exp21);
    }

    SECTION("eval cases")
    {
        const char dat1[] = "eval().bar";
        const char dat2[] = "eval()['bar']";
        const char dat3[] = "eval().bar()";
        const char dat4[] = "eval()['bar']()";
        const char dat5[] = "eval.bar";
        const char dat6[] = "eval.bar()";
        const char dat7[] = "eval['bar']";
        const char dat8[] = "eval['bar']()";
        const char dat9[] = "\\u0065\\u0076\\u0061\\u006c(\\u0062\\u0061\\u0072).\\u0062\\u0061\\u007a ;";
        const char dat10[] = "var foo.bar = 123 ; (\\u0065\\u0076\\u0061\\u006c).\\u0062\\u0061\\u007a ;";
        const char exp1[] = "eval().bar";
        const char exp2[] = "eval()['bar']";
        const char exp3[] = "eval().bar()";
        const char exp4[] = "eval()['bar']()";
        const char exp5[] = "eval.bar";
        const char exp6[] = "eval.bar()";
        const char exp7[] = "eval['bar']";
        const char exp8[] = "eval['bar']()";
        const char exp9[] = "eval(var_0000).baz;";
        const char exp10[] = "var var_0000.var_0001=123;(eval).baz;";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);
        test_normalization(dat5, exp5);
        test_normalization(dat6, exp6);
        test_normalization(dat7, exp7);
        test_normalization(dat8, exp8);
        test_normalization(dat9, exp9);
        test_normalization(dat10, exp10);
    }

    SECTION("console cases")
    {
        const char dat1[] = "console.log=abc";
        const char dat2[] = "console.log().clear()";
        const char dat3[] = "console.log(\"asd\").foo";
        const char dat4[] = "console.log[\"asd\"].foo";
        const char dat5[] = "console.log(`var a = ${ c + b }`).foo";
        const char dat6[] = "console.log(abc,def,www,document.foo(abc))";
        const char dat7[] = "console.log(document.getElementById(\"mem\").text).clear(abc)";
        const char exp1[] = "console.log=var_0000";
        const char exp2[] = "console.log().clear()";
        const char exp3[] = "console.log(\"asd\").foo";
        const char exp4[] = "console.log[\"asd\"].foo";
        const char exp5[] = "console.log(`var a = ${var_0000+var_0001}`).foo";
        const char exp6[] = "console.log(var_0000,var_0001,var_0002,document.foo(var_0000))";
        const char exp7[] = "console.log(document.getElementById(\"mem\").text).clear(var_0000)";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);
        test_normalization(dat5, exp5);
        test_normalization(dat6, exp6);
        test_normalization(dat7, exp7);
    }

    SECTION("corner cases")
    {
        const char dat1[] = "object = {hidden: eval}";
        const char dat2[] = "object = {console: \"str\"}";
        const char dat3[] = "object.hidden = eval";
        const char dat4[] = "array = [None, eval, document.getElementById]";
        const char dat5[] = "array[1] = eval";
        const char exp1[] = "var_0000={var_0001:eval}";
        const char exp2[] = "var_0000={console:\"str\"}";
        const char exp3[] = "var_0000.var_0001=eval";
        const char exp4[] = "var_0000=[var_0001,eval,document.getElementById]";
        const char exp5[] = "var_0000[1]=eval";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);
        test_normalization(dat5, exp5);
    }
}

TEST_CASE("ignored properties", "[JSNormalizer]")
{
    SECTION("basic")
    {
        const char dat1[] = "foo.bar ;";
        const char dat2[] = "foo.bar() ;";
        const char dat3[] = "foo.watch ;";
        const char dat4[] = "foo.unwatch() ;";
        const char dat5[] = "console.watch ;";
        const char dat6[] = "console.unwatch() ;";
        const char dat7[] = "console.foo.watch ;";
        const char dat8[] = "console.foo.unwatch() ;";
        const char dat9[] = "foo.console.watch ;";
        const char dat10[] = "foo.console.unwatch() ;";

        const char dat11[] = "foo['bar'] ;";
        const char dat12[] = "foo[\"bar\"]() ;";
        const char dat13[] = "foo['watch'] ;";
        const char dat14[] = "foo[\"unwatch\"]() ;";
        const char dat15[] = "console['watch'] ;";
        const char dat16[] = "console[\"unwatch\"]() ;";
        const char dat17[] = "console['foo']['watch'] ;";
        const char dat18[] = "console[\"foo\"][\"unwatch\"]() ;";
        const char dat19[] = "foo['console']['watch'] ;";
        const char dat20[] = "foo[\"console\"][\"unwatch\"]() ;";

        const char exp1[] = "var_0000.var_0001;";
        const char exp2[] = "var_0000.var_0001();";
        const char exp3[] = "var_0000.watch;";
        const char exp4[] = "var_0000.unwatch();";
        const char exp5[] = "console.watch;";
        const char exp6[] = "console.unwatch();";
        const char exp7[] = "console.foo.watch;";
        const char exp8[] = "console.foo.unwatch();";
        const char exp9[] = "var_0000.var_0001.watch;";
        const char exp10[] = "var_0000.var_0001.unwatch();";

        const char exp11[] = "var_0000['bar'];";
        const char exp12[] = "var_0000[\"bar\"]();";
        const char exp13[] = "var_0000['watch'];";
        const char exp14[] = "var_0000[\"unwatch\"]();";
        const char exp15[] = "console['watch'];";
        const char exp16[] = "console[\"unwatch\"]();";
        const char exp17[] = "console['foo']['watch'];";
        const char exp18[] = "console[\"foo\"][\"unwatch\"]();";
        const char exp19[] = "var_0000['console']['watch'];";
        const char exp20[] = "var_0000[\"console\"][\"unwatch\"]();";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);
        test_normalization(dat5, exp5);
        test_normalization(dat6, exp6);
        test_normalization(dat7, exp7);
        test_normalization(dat8, exp8);
        test_normalization(dat9, exp9);
        test_normalization(dat10, exp10);

        test_normalization(dat11, exp11);
        test_normalization(dat12, exp12);
        test_normalization(dat13, exp13);
        test_normalization(dat14, exp14);
        test_normalization(dat15, exp15);
        test_normalization(dat16, exp16);
        test_normalization(dat17, exp17);
        test_normalization(dat18, exp18);
        test_normalization(dat19, exp19);
        test_normalization(dat20, exp20);
    }

    SECTION("chain tracking")
    {
        const char dat1[] = "foo.watch.bar ;";
        const char dat2[] = "foo['watch'].bar ;";
        const char dat3[] = "foo.bar.watch.bar ;";
        const char dat4[] = "foo['bar'].watch['bar'] ;";
        const char dat5[] = "foo['bar'].watch['bar'].baz ;";

        const char dat6[] = "foo.unwatch().bar ;";
        const char dat7[] = "foo['unwatch']().bar ;";
        const char dat8[] = "foo.bar.unwatch().bar ;";
        const char dat9[] = "foo['bar'].unwatch()['bar'] ;";
        const char dat10[] = "foo['bar'].unwatch()['bar'].baz ;";

        const char dat11[] = "foo . watch \n . bar ;";
        const char dat12[] = "foo ['watch'] \n . bar ;";
        const char dat13[] = "foo . /*multiline*/ watch //oneline\n . bar ;";

        const char dat14[] = "foo . unwatch () \n . bar ;";
        const char dat15[] = "foo ['unwatch'] () \n . bar ;";
        const char dat16[] = "foo /*multiline*/ . unwatch ( ) . // oneline \n bar ;";

        const char dat17[] = "foo . + watch . bar ;";
        const char dat18[] = "foo . + ['watch'] . bar ;";

        const char dat19[] = "foo . + unwatch() . bar ;";
        const char dat20[] = "foo . + ['unwatch']() . bar ;";

        const char exp1[] = "var_0000.watch.bar;";
        const char exp2[] = "var_0000['watch'].var_0001;";
        const char exp3[] = "var_0000.var_0001.watch.bar;";
        const char exp4[] = "var_0000['bar'].watch['bar'];";
        const char exp5[] = "var_0000['bar'].watch['bar'].baz;";

        const char exp6[] = "var_0000.unwatch().bar;";
        const char exp7[] = "var_0000['unwatch']().var_0001;";
        const char exp8[] = "var_0000.var_0001.unwatch().bar;";
        const char exp9[] = "var_0000['bar'].unwatch()['bar'];";
        const char exp10[] = "var_0000['bar'].unwatch()['bar'].baz;";

        const char exp11[] = "var_0000.watch.bar;";
        const char exp12[] = "var_0000['watch'].var_0001;";
        const char exp13[] = "var_0000.watch.bar;";

        const char exp14[] = "var_0000.unwatch().bar;";
        const char exp15[] = "var_0000['unwatch']().var_0001;";
        const char exp16[] = "var_0000.unwatch().bar;";

        const char exp17[] = "var_0000.+var_0001.var_0002;";
        const char exp18[] = "var_0000.+['watch'].var_0001;";

        const char exp19[] = "var_0000.+var_0001().var_0002;";
        const char exp20[] = "var_0000.+['unwatch']().var_0001;";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);
        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);
        test_normalization(dat5, exp5);

        test_normalization(dat6, exp6);
        test_normalization(dat7, exp7);
        test_normalization(dat8, exp8);
        test_normalization(dat9, exp9);
        test_normalization(dat10, exp10);

        test_normalization(dat11, exp11);
        test_normalization(dat12, exp12);
        test_normalization(dat13, exp13);

        test_normalization(dat14, exp14);
        test_normalization(dat15, exp15);
        test_normalization(dat16, exp16);

        test_normalization(dat17, exp17);
        test_normalization(dat18, exp18);

        test_normalization(dat19, exp19);
        test_normalization(dat20, exp20);
    }

    SECTION("scope tracking")
    {
        const char dat1[] = "foo.(watch).bar ;";
        const char dat2[] = "foo(['watch']).bar ;";

        const char dat3[] = "foo.bar(baz.unwatch.eval).eval ;";
        const char dat4[] = "foo.bar(baz['unwatch'].eval).eval ;";

        const char exp1[] = "var_0000.(var_0001).var_0002;";
        const char exp2[] = "var_0000(['watch']).var_0001;";

        const char exp3[] = "var_0000.var_0001(var_0002.unwatch.eval).var_0003;";
        const char exp4[] = "var_0000.var_0001(var_0002['unwatch'].var_0003).var_0003;";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);

        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);
    }

    SECTION("corner cases")
    {
        const char dat1[] = ".watch ;";
        const char dat2[] = ".unwatch() ;";

        const char dat3[] = "'foo'.watch ;";
        const char dat4[] = "\"foo\".unwatch() ;";

        const char dat5[] = "''.split('').reverse().join('') ;";
        const char dat6[] = "\"\".split(\"\").reverse().join(\"\") ;";

        const char dat7[] = "watch () ;";
        const char dat8[] = "watch.watch() ;";

        // 'name' is present in both ignore lists
        const char dat9[] = "name.foo ;";
        const char dat10[] = "foo.name ;";
        const char dat11[] = "name.name ;";
        const char dat12[] = "name ;";

        const char dat13[] = "foo.foo ;";
        const char dat14[] = "console.console; console;";
        const char dat15[] = "watch.watch; watch;";
        const char dat16[] = "foo.console; console.foo; foo.watch; watch.foo ;";
        const char dat17[] = "console.foo; foo.console; watch.foo; foo.watch ;";

        const char dat18[] = "a.a ;";
        const char dat19[] = "u.u; u;";
        const char dat20[] = "w.w; w;";
        const char dat21[] = "a.u; u.a; a.w; w.a ;";
        const char dat22[] = "u.a; a.u; w.a; a.w ;";

        const char exp1[] = ".watch;";
        const char exp2[] = ".unwatch();";

        const char exp3[] = "'foo'.watch;";
        const char exp4[] = "\"foo\".unwatch();";

        const char exp5[] = "''.split('').reverse().join('');";
        const char exp6[] = "\"\".split(\"\").reverse().join(\"\");";

        const char exp7[] = "var_0000();";
        const char exp8[] = "var_0000.watch();";

        const char exp9[] = "name.foo;";
        const char exp10[] = "var_0000.name;";
        const char exp11[] = "name.name;";
        const char exp12[] = "name;";

        const char exp13[] = "var_0000.var_0000;";
        const char exp14[] = "console.console;console;";
        const char exp15[] = "var_0000.watch;var_0000;";
        const char exp16[] = "var_0000.var_0001;console.foo;var_0000.watch;var_0002.var_0000;";
        const char exp17[] = "console.foo;var_0000.var_0001;var_0002.var_0000;var_0000.watch;";

        const char exp18[] = "var_0000.var_0000;";
        const char exp19[] = "u.u;u;";
        const char exp20[] = "var_0000.w;var_0000;";
        const char exp21[] = "var_0000.var_0001;u.a;var_0000.w;var_0002.var_0000;";
        const char exp22[] = "u.a;var_0000.var_0001;var_0002.var_0000;var_0000.w;";

        test_normalization(dat1, exp1);
        test_normalization(dat2, exp2);

        test_normalization(dat3, exp3);
        test_normalization(dat4, exp4);

        test_normalization(dat5, exp5);
        test_normalization(dat6, exp6);

        test_normalization(dat7, exp7);
        test_normalization(dat8, exp8);

        test_normalization(dat9, exp9);
        test_normalization(dat10, exp10);
        test_normalization(dat11, exp11);
        test_normalization(dat12, exp12);

        test_normalization(dat13, exp13);
        test_normalization(dat14, exp14);
        test_normalization(dat15, exp15);
        test_normalization(dat16, exp16);
        test_normalization(dat17, exp17);

        test_normalization(dat18, exp18);
        test_normalization(dat19, exp19);
        test_normalization(dat20, exp20);
        test_normalization(dat21, exp21);
        test_normalization(dat22, exp22);
    }
}

TEST_CASE("ignored identifier split", "[JSNormalizer]")
{
#if JSTOKENIZER_MAX_STATES != 8
#error "ignored identifier split" tests are designed for 8 states depth
#endif

    SECTION("a standalone identifier")
    {
        const char dat1[] = "con";
        const char dat2[] = "sole";
        const char dat3[] = "e";
        const char dat4[] = "val";
        const char dat5[] = "console . ";
        const char dat6[] = "foo";
        const char dat7[] = "eval ";
        const char dat8[] = ". bar";
        const char exp1[] = "var_0000";
        const char exp2[] = "console";
        const char exp3[] = "var_0000";
        const char exp4[] = "eval";
        const char exp5[] = "console.";
        const char exp6[] = "foo";
        const char exp7[] = "eval";
        const char exp8[] = ".bar";

        const char exp9[] = "console";
        const char exp10[] = "eval";
        const char exp11[] = "console.foo";
        const char exp12[] = "eval.bar";

        test_normalization(
            {
                 {dat1, exp1},
                 {dat2, exp2},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat1, dat2}, exp9);

        test_normalization(
            {
                 {dat3, exp3},
                 {dat4, exp4},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat3, dat4}, exp10);

        test_normalization(
            {
                 {dat5, exp5},
                 {dat6, exp6},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat5, dat6}, exp11);

        test_normalization(
            {
                 {dat7, exp7},
                 {dat8, exp8},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat7, dat8}, exp12);
    }

    SECTION("function calls")
    {
        const char dat1[] = "console";
        const char dat2[] = "().foo";
        const char dat3[] = "console(";
        const char dat4[] = ").foo";
        const char dat5[] = "console()";
        const char dat6[] = ".foo";
        const char dat7[] = "console().";
        const char dat8[] = "foo";
        const char dat9[] = "console().re";
        const char dat10[] = "write";
        const char exp1[] = "console";
        const char exp2[] = "().foo";
        const char exp3[] = "console(";
        const char exp4[] = ").foo";
        const char exp5[] = "console()";
        const char exp6[] = ".foo";
        const char exp7[] = "console().";
        const char exp8[] = "foo";
        const char exp9[] = "console().re";
        const char exp10[] = "rewrite";

        const char exp11[] = "console().foo";
        const char exp12[] = "console().foo";
        const char exp13[] = "console().foo";
        const char exp14[] = "console().foo";
        const char exp15[] = "console().rewrite";

        test_normalization(
            {
                 {dat1, exp1},
                 {dat2, exp2},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat1, dat2}, exp11);

        test_normalization(
            {
                 {dat3, exp3},
                 {dat4, exp4},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat3, dat4}, exp12);

        test_normalization(
            {
                 {dat5, exp5},
                 {dat6, exp6},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat5, dat6}, exp13);

        test_normalization(
            {
                 {dat7, exp7},
                 {dat8, exp8},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat7, dat8}, exp14);

        test_normalization(
            {
                 {dat9, exp9},
                 {dat10, exp10},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat9, dat10}, exp15);
    }

    SECTION("terminator split")
    {
        const char dat1[] = "eval.foo ";
        const char dat2[] = "bar.baz";
        const char dat3[] = "eval.foo";
        const char dat4[] = " bar.baz";
        const char dat5[] = "eval.foo;";
        const char dat6[] = "bar.baz";
        const char dat7[] = "eval.foo";
        const char dat8[] = ";bar.baz";
        const char dat9[] = "eval.foo%";
        const char dat10[] = "=bar.baz";
        const char exp1[] = "eval.foo";
        const char exp2[] = " var_0000.var_0001";
        const char exp3[] = "eval.foo";
        const char exp4[] = " var_0000.var_0001";
        const char exp5[] = "eval.foo;";
        const char exp6[] = "var_0000.var_0001";
        const char exp7[] = "eval.foo";
        const char exp8[] = ";var_0000.var_0001";
        const char exp9[] = "eval.foo%";
        const char exp10[] = "%=var_0000.var_0001";

        const char exp11[] = "eval.foo var_0000.var_0001";
        const char exp12[] = "eval.foo var_0000.var_0001";
        const char exp13[] = "eval.foo;var_0000.var_0001";
        const char exp14[] = "eval.foo;var_0000.var_0001";
        const char exp15[] = "eval.foo%=var_0000.var_0001";

        test_normalization(
            {
                 {dat1, exp1},
                 {dat2, exp2},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat1, dat2}, exp11);

        test_normalization(
            {
                 {dat3, exp3},
                 {dat4, exp4},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat3, dat4}, exp12);

        test_normalization(
            {
                 {dat5, exp5},
                 {dat6, exp6},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat5, dat6}, exp13);

        test_normalization(
            {
                 {dat7, exp7},
                 {dat8, exp8},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat7, dat8}, exp14);

        test_normalization(
            {
                 {dat9, exp9},
                 {dat10, exp10},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat9, dat10}, exp15);
    }

    SECTION("scope split")
    {
        // "eval(foo,eval(bar,eval(baz[''].console.check+check).foo).bar).baz+check"
        //                   split here ^

        const char dat1[] = "eval(foo,eval(bar,eval(baz['";
        const char dat2[] = "'].console.check+check).foo).bar).baz+check";
        const char exp1[] = "eval(var_0000,eval(var_0001,eval(var_0002['";
        const char exp2[] = "'].var_0003.var_0004+var_0004).foo).bar).baz+var_0004";

        const char exp3[] = "eval(var_0000,eval(var_0001,eval(var_0002['"
            "'].var_0003.var_0004+var_0004).foo).bar).baz+var_0004";

        test_normalization(
            {
                 {dat1, exp1},
                 {dat2, exp2},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat1, dat2}, exp3);

        // "eval(foo,eval(bar,eval(baz[''].console.check+check).foo).bar).baz+check"
        //                         split here ^

        const char dat3[] = "eval(foo,eval(bar,eval(baz[''].con";
        const char dat4[] = "sole.check+check).foo).bar).baz+check";
        const char exp4[] = "eval(var_0000,eval(var_0001,eval(var_0002[''].var_0003";
        const char exp5[] = "var_0004.var_0005+var_0005).foo).bar).baz+var_0005";

        const char exp6[] = "eval(var_0000,eval(var_0001,eval(var_0002['']."
            "var_0004.var_0005+var_0005).foo).bar).baz+var_0005";

        test_normalization(
            {
                 {dat3, exp4},
                 {dat4, exp5},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat3, dat4}, exp6);

        // "eval(foo,eval(bar,eval(baz[''].console.check+check).foo).bar).baz+check"
        //                                              split here ^

        const char dat5[] = "eval(foo,eval(bar,eval(baz[''].console.check+check).foo";
        const char dat6[] = ").bar).baz+check";
        const char exp7[] = "eval(var_0000,eval(var_0001,eval(var_0002[''].var_0003.var_0004+var_0004).foo";
        const char exp8[] = ").bar).baz+var_0004";

        const char exp9[] = "eval(var_0000,eval(var_0001,eval(var_0002[''].var_0003.var_0004+var_0004).foo"
            ").bar).baz+var_0004";

        test_normalization(
            {
                 {dat5, exp7},
                 {dat6, exp8},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat5, dat6}, exp9);
    }

    SECTION("normalized word in the previous PDU")
    {
        const char dat1[] = "!foo";
        const char dat2[] = "()";
        const char exp1[] = "!var_0000";
        const char exp2[] = "()";

        test_normalization(
            {
                 {dat1, exp1},
                 {dat2, exp2},
            },
            {use_expected_for_last_pdu(true)}
       );
    }

    SECTION("ignored word in the previous PDU")
    {
        const char dat1[] = "!eval";
        const char dat2[] = "()";
        const char exp1[] = "!eval";
        const char exp2[] = "()";

        test_normalization(
            {
                 {dat1, exp1},
                 {dat2, exp2},
            },
            {use_expected_for_last_pdu(true)}
       );
    }
}

TEST_CASE("ignored properties split", "[JSNormalizer]")
{
#if JSTOKENIZER_MAX_STATES != 8
#error "ignored properties split" tests are designed for 8 states depth
#endif

    SECTION("a standalone property")
    {
        const char dat1[] = "foo.un";
        const char dat2[] = "watch ;";
        const char exp1[] = "var_0000.var_0001";
        const char exp2[] = "unwatch;";
        const char exp_comb_1[] = "var_0000.unwatch;";

        const char dat3[] = "foo. un";
        const char dat4[] = "watch () ;";
        const char exp3[] = "var_0000.var_0001";
        const char exp4[] = "unwatch();";
        const char exp_comb_2[] = "var_0000.unwatch();";

        const char dat5[] = "fo";
        const char dat6[] = "o . watch ;";
        const char exp5[] = "var_0000";
        const char exp6[] = "var_0001.watch;";
        const char exp_comb_3[] = "var_0001.watch;";

        const char dat7[] = "foo. ";
        const char dat8[] = "watch ;";
        const char exp7[] = "var_0000.";
        const char exp8[] = "watch;";
        const char exp_comb_4[] = "var_0000.watch;";

        const char dat9[] = "foo ";
        const char dat10[] = ". watch ;";
        const char exp9[] = "var_0000";
        const char exp10[] = ".watch;";
        const char exp_comb_5[] = "var_0000.watch;";

        test_normalization(
            {
                 {dat1, exp1},
                 {dat2, exp2},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat1, dat2}, exp_comb_1);

        test_normalization(
            {
                 {dat3, exp3},
                 {dat4, exp4},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat3, dat4}, exp_comb_2);

        test_normalization(
            {
                 {dat5, exp5},
                 {dat6, exp6},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat5, dat6}, exp_comb_3);

        test_normalization(
            {
                 {dat7, exp7},
                 {dat8, exp8},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat7, dat8}, exp_comb_4);

        test_normalization(
            {
                 {dat9, exp9},
                 {dat10, exp10},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat9, dat10}, exp_comb_5);
    }

    SECTION("chain tracking")
    {
        const char dat1[] = "foo.un";
        const char dat2[] = "watch.bar ;";
        const char exp1[] = "var_0000.var_0001";
        const char exp2[] = "unwatch.bar;";
        const char exp_comb_1[] = "var_0000.unwatch.bar;";

        const char dat3[] = "foo.un";
        const char dat4[] = "watch().bar ;";
        const char exp3[] = "var_0000.var_0001";
        const char exp4[] = "unwatch().bar;";
        const char exp_comb_2[] = "var_0000.unwatch().bar;";

        const char dat5[] = "foo['un";
        const char dat6[] = "watch'].bar ;";
        const char exp5[] = "var_0000['un";
        const char exp6[] = "unwatch'].var_0001;";
        const char exp_comb_3[] = "var_0000['unwatch'].var_0001;";

        const char dat7[] = "foo['un";
        const char dat8[] = "watch']().bar ;";
        const char exp7[] = "var_0000['un";
        const char exp8[] = "unwatch']().var_0001;";
        const char exp_comb_4[] = "var_0000['unwatch']().var_0001;";

        const char dat9[] = "foo. /*multi";
        const char dat10[] = "line*/ watch . bar ;";
        const char exp9[] = "var_0000.";
        const char exp10[] = "watch.bar;";
        const char exp_comb_5[] = "var_0000.watch.bar;";

        const char dat11[] = "foo //one";
        const char dat12[] = "line \n . watch . bar ;";
        const char exp11[] = "var_0000";
        const char exp12[] = ".watch.bar;";
        const char exp_comb_6[] = "var_0000.watch.bar;";

        const char dat13[] = ".";
        const char dat14[] = "watch ( ) . bar ;";
        const char exp13[] = ".";
        const char exp14[] = "watch().bar;";
        const char exp_comb_7[] = ".watch().bar;";

        const char dat15[] = ".un";
        const char dat16[] = "watch ( ) . bar ;";
        const char exp15[] = ".var_0000";
        const char exp16[] = "unwatch().bar;";
        const char exp_comb_8[] = ".unwatch().bar;";

        const char dat17[] = "foo.watch ";
        const char dat18[] = "+ bar ;";
        const char exp17[] = "var_0000.watch";
        const char exp18[] = "+var_0001;";
        const char exp_comb_9[] = "var_0000.watch+var_0001;";

        const char dat19[] = "foo.unwatch ( ) +";
        const char dat20[] = "bar ;";
        const char exp19[] = "var_0000.unwatch()+";
        const char exp20[] = "var_0001;";
        const char exp_comb_10[] = "var_0000.unwatch()+var_0001;";

        test_normalization(
            {
                 {dat1, exp1},
                 {dat2, exp2},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat1, dat2}, exp_comb_1);

        test_normalization(
            {
                 {dat3, exp3},
                 {dat4, exp4},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat3, dat4}, exp_comb_2);

        test_normalization(
            {
                 {dat5, exp5},
                 {dat6, exp6},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat5, dat6}, exp_comb_3);

        test_normalization(
            {
                 {dat7, exp7},
                 {dat8, exp8},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat7, dat8}, exp_comb_4);

        test_normalization(
            {
                 {dat9, exp9},
                 {dat10, exp10},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat9, dat10}, exp_comb_5);

        test_normalization(
            {
                 {dat11, exp11},
                 {dat12, exp12},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat11, dat12}, exp_comb_6);

        test_normalization(
            {
                 {dat13, exp13},
                 {dat14, exp14},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat13, dat14}, exp_comb_7);

        test_normalization(
            {
                 {dat15, exp15},
                 {dat16, exp16},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat15, dat16}, exp_comb_8);

        test_normalization(
            {
                 {dat17, exp17},
                 {dat18, exp18},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat17, dat18}, exp_comb_9);

        test_normalization(
            {
                 {dat19, exp19},
                 {dat20, exp20},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat19, dat20}, exp_comb_10);
    }

    SECTION("scope tracking")
    {
        const char dat1[] = "foo.(un";
        const char dat2[] = "watch).bar ;";
        const char exp1[] = "var_0000.(var_0001";
        const char exp2[] = "var_0002).var_0003;";
        const char exp_comb_1[] = "var_0000.(var_0002).var_0003;";

        const char dat3[] = "foo(['un";
        const char dat4[] = "watch']).bar ;";
        const char exp3[] = "var_0000(['un";
        const char exp4[] = "unwatch']).var_0001;";
        const char exp_comb_2[] = "var_0000(['unwatch']).var_0001;";

        const char dat5[] = "foo.bar(baz.un";
        const char dat6[] = "watch() . bar ) . foo ;";
        const char exp5[] = "var_0000.var_0001(var_0002.var_0003";
        const char exp6[] = "unwatch().bar).var_0000;";
        const char exp_comb_3[] = "var_0000.var_0001(var_0002.unwatch().bar).var_0000;";

        const char dat7[] = "foo.bar(baz['un";
        const char dat8[] = "watch']() . bar ) . foo ;";
        const char exp7[] = "var_0000.var_0001(var_0002['un";
        const char exp8[] = "unwatch']().var_0001).var_0000;";
        const char exp_comb_4[] = "var_0000.var_0001(var_0002['unwatch']().var_0001).var_0000;";

        test_normalization(
            {
                 {dat1, exp1},
                 {dat2, exp2},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat1, dat2}, exp_comb_1);

        test_normalization(
            {
                 {dat3, exp3},
                 {dat4, exp4},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat3, dat4}, exp_comb_2);

        test_normalization(
            {
                 {dat5, exp5},
                 {dat6, exp6},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat5, dat6}, exp_comb_3);

        test_normalization(
            {
                 {dat7, exp7},
                 {dat8, exp8},
            },
            {use_expected_for_last_pdu(true)});
        test_normalization_combined({dat7, dat8}, exp_comb_4);
    }
}

TEST_CASE("Scope tracking - basic", "[JSNormalizer]")
{
    SECTION("Global only")
        test_scope("", {GLOBAL});

    SECTION("Function scope - named function")
        test_scope("function f(){", {GLOBAL, FUNCTION});

    SECTION("Function scope - anonymous function")
        test_scope("var f = function(){", {GLOBAL, FUNCTION});

    SECTION("Function scope - arrow function")
        test_scope("var f = (a,b)=>{", {GLOBAL, FUNCTION});

    SECTION("Function scope - arrow function without scope")
        test_scope("var f = (a,b)=> a", {GLOBAL, FUNCTION});

    SECTION("Function scope - function call in an arrow function without scope")
        test_scope("var f = (a,b)=> call(", {GLOBAL, FUNCTION});

    SECTION("Function scope - method in object initialization")
        test_scope("var o = { f(){", {GLOBAL, BLOCK, BLOCK});

    SECTION("Function scope - method in object operation")
        test_scope("+{ f(){", {GLOBAL, BLOCK, BLOCK});

    SECTION("Function scope - method in object as a function parameter")
        test_scope("call({ f(){", {GLOBAL, BLOCK, BLOCK});

    SECTION("Function scope - keyword name method")
        test_scope("var o = { let(){", {GLOBAL, BLOCK, BLOCK});

    SECTION("Function scope - 'get' name method")
        test_scope("var o = { get(){", {GLOBAL, BLOCK, BLOCK});

    SECTION("Function scope - expression method")
        test_scope("var o = { [a + 12](){", {GLOBAL, BLOCK, BLOCK});

    SECTION("Function scope - method as anonymous function")
        test_scope("var o = { f: function(){", {GLOBAL, BLOCK, FUNCTION});

    SECTION("Function scope - keyword name method as anonymous function")
        test_scope("var o = { let: function(){", {GLOBAL, BLOCK, FUNCTION});

    SECTION("Function scope - 'get' name method as anonymous function")
        test_scope("var o = { get: function(){", {GLOBAL, BLOCK, FUNCTION});

    SECTION("Function scope - expression method as anonymous function")
        test_scope("var o = { [a + 12]: function(){", {GLOBAL, BLOCK, FUNCTION});

    SECTION("Function scope - getter")
        test_scope("var o = { get f(){", {GLOBAL, BLOCK, BLOCK});

    SECTION("Function scope - parametric getter")
        test_scope("var o = { get [a + 12](){", {GLOBAL, BLOCK, BLOCK});

    SECTION("Function scope - setter")
        test_scope("var o = { set f(){", {GLOBAL, BLOCK, BLOCK});

    SECTION("Function scope - parametric setter")
        test_scope("var o = { set [a + 12](){", {GLOBAL, BLOCK, BLOCK});

    SECTION("Block scope - regular block")
        test_scope("{", {GLOBAL, BLOCK});

    SECTION("Block scope - object initializer")
        test_scope("o = {", {GLOBAL, BLOCK});

    SECTION("Block scope - class")
        test_scope("class C{", {GLOBAL, BLOCK});

    SECTION("Block scope - class with extends")
        test_scope("class C extends A{", {GLOBAL, BLOCK});

    SECTION("Block scope - if")
        test_scope("if(true){", {GLOBAL, BLOCK});

    SECTION("Block scope - single statement if")
        test_scope("if(true) func()", {GLOBAL, BLOCK});

    SECTION("Block scope - nested multiple single statement ifs")
        test_scope("if(a) if(b) if(c) if(d) func()", {GLOBAL, BLOCK});

    SECTION("Block scope - nested multiple single statement ifs with newline")
        test_scope("if(a)\nif(b)\nif(c)\nif(d)\nfunc()", {GLOBAL, BLOCK});

    SECTION("Block scope - else")
        test_scope("if(true);else{", {GLOBAL, BLOCK});

    SECTION("Block scope - single statement else")
        test_scope("if(true);else func()", {GLOBAL, BLOCK});

    SECTION("Block scope - for loop")
        test_scope("for(;;){", {GLOBAL, BLOCK});

    SECTION("Block scope - for loop in range")
        test_scope("for(i in range()){", {GLOBAL, BLOCK});

    SECTION("Block scope - for loop of iterable")
        test_scope("for(i of o){", {GLOBAL, BLOCK});

    SECTION("Block scope - for await loop")
        test_scope("for await(i of o){", {GLOBAL, BLOCK});

    SECTION("Block scope - inside for statement")
        test_scope("for(", {GLOBAL, BLOCK});

    SECTION("Block scope - inside for statement, after semicolon")
        test_scope("for(;", {GLOBAL, BLOCK});

    SECTION("Block scope - single statement for")
        test_scope("for(;;) func()", {GLOBAL, BLOCK});

    SECTION("Block scope - for nested in single line conditional")
        test_scope("if(true) for(;;) a++", {GLOBAL, BLOCK});

    SECTION("Block scope - while")
        test_scope("while(true){", {GLOBAL, BLOCK});

    SECTION("Block scope - single statement while")
        test_scope("while(true) func()", {GLOBAL, BLOCK});

    SECTION("Block scope - do-while")
        test_scope("do{", {GLOBAL, BLOCK});

    SECTION("Block scope - single statement do-while")
        test_scope("do func()", {GLOBAL, BLOCK});

    SECTION("Block scope - try")
        test_scope("try{", {GLOBAL, BLOCK});

    SECTION("Block scope - catch")
        test_scope("try{}catch(e){", {GLOBAL, BLOCK});

    SECTION("Block scope - catch exception declaration")
        test_scope("try{}catch(", {GLOBAL, BLOCK});

    SECTION("Block scope - finally")
        test_scope("try{}finally{", {GLOBAL, BLOCK});

    SECTION("Block scope - nested object - named")
        test_scope("var o = {s:{", {GLOBAL, BLOCK, BLOCK});

    SECTION("Block scope - nested object - keyword named")
        test_scope("var o = {let:{", {GLOBAL, BLOCK, BLOCK});

    SECTION("Block scope - nested object - 'get' named")
        test_scope("var o = {get:{", {GLOBAL, BLOCK, BLOCK});

    SECTION("Block scope - nested object - parametric")
        test_scope("var o = {[a+12]:{", {GLOBAL, BLOCK, BLOCK});
}

TEST_CASE("Scope tracking - closing", "[JSNormalizer]")
{

    SECTION("Function scope - named function")
        test_scope("function f(){}", {GLOBAL});

    SECTION("Function scope - anonymous function")
        test_scope("var f = function(){}", {GLOBAL});

    SECTION("Function scope - arrow function")
        test_scope("var f = (a, b)=>{}", {GLOBAL});

    SECTION("Function scope - arrow function without scope")
        test_scope("var f = (a, b)=>a;", {GLOBAL});

    SECTION("Function scope - function call in an arrow function without scope")
        test_scope("var f = a=>call();", {GLOBAL});

    SECTION("Function scope - arrow function as a function parameter")
        test_scope("console.log(a=>c)", {GLOBAL});

    SECTION("Function scope - method")
        test_scope("var o = { f(){}", {GLOBAL, BLOCK});

    SECTION("Function scope - keyword name method")
        test_scope("var o = { let(){}", {GLOBAL, BLOCK});

    SECTION("Function scope - expression method")
        test_scope("var o = { [a + 12](){}", {GLOBAL, BLOCK});

    SECTION("Function scope - method as anonymous function")
        test_scope("var o = { f: function(){}", {GLOBAL, BLOCK});

    SECTION("Function scope - keyword name method as anonymous function")
        test_scope("var o = { let: function(){}", {GLOBAL, BLOCK});

    SECTION("Function scope - expression method as anonymous function")
        test_scope("var o = { [a + 12]: function(){}", {GLOBAL, BLOCK});

    SECTION("Function scope - getter")
        test_scope("var o = { get f(){}", {GLOBAL, BLOCK});

    SECTION("Function scope - parametric getter")
        test_scope("var o = { get [a + 12](){}", {GLOBAL, BLOCK});

    SECTION("Function scope - setter")
        test_scope("var o = { set f(){}", {GLOBAL, BLOCK});

    SECTION("Function scope - parametric setter")
        test_scope("var o = { set [a + 12](){}", {GLOBAL, BLOCK});

    SECTION("Block scope - regular block")
        test_scope("{}", {GLOBAL});

    SECTION("Block scope - object initializer")
        test_scope("o = {}", {GLOBAL});

    SECTION("Block scope - class")
        test_scope("class C{}", {GLOBAL});

    SECTION("Block scope - class with extends")
        test_scope("class C extends A{}", {GLOBAL});

    SECTION("Block scope - if")
        test_scope("if(true){}", {GLOBAL});

    SECTION("Block scope - single statement if")
        test_scope("if(true);", {GLOBAL});

    SECTION("Block scope - single statement if, semicolon group terminated")
        test_scope("if(true)\na++\nreturn", {GLOBAL});

    SECTION("Block scope - nested multiple single statement ifs")
        test_scope("if(a) if(b) if(c) if(d) func();", {GLOBAL});

    SECTION("Block scope - nested multiple single statement ifs with newline")
        test_scope("if(a)\nif(b)\nif(c)\nif(d)\nfunc()\nfunc()", {GLOBAL});

    SECTION("Block scope - else")
        test_scope("if(true);else{}", {GLOBAL});

    SECTION("Block scope - single statement else")
        test_scope("if(true);else;", {GLOBAL});

    SECTION("Block scope - for loop")
        test_scope("for(;;){}", {GLOBAL});

    SECTION("Block scope - for loop in range")
        test_scope("for(i in range()){}", {GLOBAL});

    SECTION("Block scope - for loop of iterable")
        test_scope("for(i of o){}", {GLOBAL});

    SECTION("Block scope - for await loop")
        test_scope("for await(i of o){}", {GLOBAL});

    SECTION("Block scope - single statement for")
        test_scope("for(;;);", {GLOBAL});

    SECTION("Block scope - while")
        test_scope("while(true){}", {GLOBAL});

    SECTION("Block scope - single statement while")
        test_scope("while(true);", {GLOBAL});

    SECTION("Block scope - do-while")
        test_scope("do{}while(", {GLOBAL, BLOCK});

    SECTION("Block scope - single statement do-while")
        test_scope("do;while(", {GLOBAL, BLOCK});

    SECTION("Block scope - try")
        test_scope("try{}", {GLOBAL});

    SECTION("Block scope - catch")
        test_scope("try{}catch(e){}", {GLOBAL});

    SECTION("Block scope - finally")
        test_scope("try{}finally{}", {GLOBAL});

    SECTION("Block scope - nested object - named")
        test_scope("var o = {s:{}", {GLOBAL, BLOCK});

    SECTION("Block scope - nested object - keyword named")
        test_scope("var o = {let:{}", {GLOBAL, BLOCK});

    SECTION("Block scope - nested object - parametric")
        test_scope("var o = {[a+12]:{}", {GLOBAL, BLOCK});

    SECTION("Block scope - advanced automatic semicolon insertion")
        test_scope(
            "var\na\n=\n0\n\n"                                      // var a=0;
            "for\n(\nlet\na\n=\n0\na\n<\n5\n++\na\n)\na\n+=\n2\n\n" // for (let a = 0;a<5;++a) a+=2;
            "do\nlet\na\n=\n0\nwhile\n(\na\n<\n5\n)\n\n"            // do let a=0; while (a < 5);
            "++\na\n\n"                                             // ++a;
            "while\n(a\n<\n5\n)\na\n+=\n2\n\n"                      // while (a<5) a+=2;
            "if\n(\ntrue\n)\nlet\na\n=\n0\n\n"                      // if (true) let a=0;
            "else\nlet\na\n=\n0\n\na;",                             // else let a=0;a;
            {GLOBAL}
        );

    SECTION("Block scope - inline block in the end of outer scope")
        test_scope("function() { if (true)\nfor ( ; ; ) a = 2 }", {GLOBAL});
}

TEST_CASE("Scope tracking - over multiple PDU", "[JSNormalizer]")
{
    // Every line represents a PDU. Each pdu has input buffer, expected script
    // and expected scope stack, written in that order
    SECTION("general - variable extension")
        test_normalization({
            {"long_", "var_0000", {GLOBAL}},
            {"variable", "var_0001", {GLOBAL}}
            //FIXIT-E: if variable index will be preserved across PDUs, second pdu expected
            // will be "var_0000"
        });

    SECTION("general - variable extension: ignored identifier to a regular one")
        test_normalization({
            {"console", "console", {GLOBAL}},
            {"Writer", "var_0000", {GLOBAL}}
        });

    SECTION("general - variable extension: a regular identifier to ignored one")
        test_normalization({
            {"con", "var_0000", {GLOBAL}},
            {"sole", "console", {GLOBAL}}
        });

    SECTION("general - variable extension that overwrites existing variable")
        test_normalization({
            {"a, b, an", "var_0000,var_0001,var_0002", {GLOBAL}},
            {"other = a", "var_0000,var_0001,var_0003=var_0000", {GLOBAL}}
        });

    SECTION("general - variable extension that overwrites existing variable inside inner scope")
        test_normalization({
            {"f(a, x=>{var an", "var_0000(var_0001,var_0002=>{var var_0003", {GLOBAL, FUNCTION}},
            {"other = a})", "var_0000(var_0001,var_0002=>{var var_0004=var_0001})", {GLOBAL}}
        });

    SECTION("block scope - basic open")
        test_normalization({
            {"{", "{", {GLOBAL, BLOCK}},
            {"var", "{var", {GLOBAL, BLOCK}}
        });

    SECTION("block scope - basic close")
        test_normalization({
            {"{", "{", {GLOBAL, BLOCK}},
            {"}", "{}", {GLOBAL}}
        });

    SECTION("block scope - open outside cross-PDU states")
        test_normalization({
            {"{[1,2,3,4,5,6,7,8]", "{[1,2,3,4,5,6,7,8]", {GLOBAL, BLOCK}},
            {"}", "{[1,2,3,4,5,6,7,8]}", {GLOBAL}}
        });

    SECTION("block scope - closing brace in a string")
        test_normalization({
            {"{[1,2,3,4,5,6,7,'}']", "{[1,2,3,4,5,6,7,'}']", {GLOBAL, BLOCK}},
            {"}", "{[1,2,3,4,5,6,7,'}']}", {GLOBAL}}
        });

    SECTION("block scope - for keyword split")
        test_normalization({
            {"fin", "var_0000", {GLOBAL}},
            {"ally {", "finally{", {GLOBAL, BLOCK}}
        });

    SECTION("block scope - between 'for' and '('")
        test_normalization({
            {"for", "for", {GLOBAL, BLOCK}},
            {"(", "for(", {GLOBAL, BLOCK}}
        });

    SECTION("block scope - fake 'for'")
        test_normalization({
            {"for", "for", {GLOBAL, BLOCK}},
            {"k", "var_0000", {GLOBAL}}
        });

    SECTION("block scope - inside for-loop parentheses")
        test_normalization({
            {"for(;;", "for(;;", {GLOBAL, BLOCK}},
            {");", "for(;;);", {GLOBAL}}
        });

    SECTION("block scope - between for-loop parentheses and code block")
        test_normalization({
            {"for(;;)", "for(;;)", {GLOBAL, BLOCK}},
            {"{}", "for(;;){}", {GLOBAL}}
        });

    SECTION("function scope: split in 'function'")
        test_normalization({
            {"func", "var_0000", {GLOBAL}},
            {"tion(", "function(", {GLOBAL, FUNCTION}}
        });

    SECTION("function scope: fake function")
        test_normalization({
            {"function", "function", {GLOBAL}},
            {"al(", "var_0000(", {GLOBAL}}
        });

    SECTION("function scope: split inside string literal")
        test_normalization({
            {"`$$$$$$$$function", "`$$$$$$$$function", {GLOBAL}},
            {"(){a = 0", "`$$$$$$$$function(){a = 0", {GLOBAL}}
        });

    SECTION("function scope: inside parameters")
        test_normalization({
            {"function(", "function(", {GLOBAL, FUNCTION}},
            {")", "function()", {GLOBAL, FUNCTION}}
        });

    SECTION("function scope: between parameters and body")
        test_normalization({
            {"function()", "function()", {GLOBAL, FUNCTION}},
            {"{", "function(){", {GLOBAL, FUNCTION}}
        });

    SECTION("function scope: inside code")
        test_normalization({
            {"function(){", "function(){", {GLOBAL, FUNCTION}},
            {"}", "function(){}", {GLOBAL}}
        });

    SECTION("object initializer: basic")
        test_normalization({
            {"var o = {", "var var_0000={", {GLOBAL, BLOCK}},
            {"}", "var var_0000={}", {GLOBAL}}
        });

    SECTION("false var keyword")
        test_normalization({
            {"var var_a; function(){ var", "var var_0000;function(){var", {GLOBAL, FUNCTION}},
            {"_a; }", "var var_0000;function(){var_0000;}", {GLOBAL}}
        });

    SECTION("false let keyword")
        test_normalization({
            {"var let_a; function(){ let", "var var_0000;function(){let", {GLOBAL, FUNCTION}},
            {"_a; }", "var var_0000;function(){var_0000;}", {GLOBAL}}
        });

    SECTION("false const keyword")
        test_normalization({
            {"var const_a; function(){ const", "var var_0000;function(){const", {GLOBAL, FUNCTION}},
            {"_a; }", "var var_0000;function(){var_0000;}", {GLOBAL}}
        });

    SECTION("false class keyword")
        test_normalization({
            {"var a; class", "var var_0000;class", {GLOBAL}},
            {"_a; { a }", "var var_0000;var_0001;{var_0000}", {GLOBAL}}
        });
}

TEST_CASE("Scope tracking - error handling", "[JSNormalizer]")
{
    SECTION("not identifier after var keyword")
        test_normalization_bad(
            "var +;",
            "var",
            JSTokenizer::BAD_TOKEN
        );

    SECTION("not identifier after let keyword")
        test_normalization_bad(
            "let class;",
            "let",
            JSTokenizer::BAD_TOKEN
        );

    SECTION("not identifier after const keyword")
        test_normalization_bad(
            "const 1;",
            "const",
            JSTokenizer::BAD_TOKEN
        );

    SECTION("scope mismatch")
        test_normalization_bad(
            "function f() { if (true)} }",
            "function var_0000(){if(true)}",
            JSTokenizer::WRONG_CLOSING_SYMBOL
        );

    SECTION("scope mismatch with code block")
        test_normalization_bad(
            "{ { function } }",
            "{{function",
            JSTokenizer::WRONG_CLOSING_SYMBOL
        );

    SECTION("scope nesting overflow")
    {
        const char src[] = "function() { if (true) { } }";
        const char exp[] = "function(){if";

        test_normalization(src, exp,
            {max_scope_depth(2), return_code(JSTokenizer::SCOPE_NESTING_OVERFLOW)});
    }
}

TEST_CASE("Function call tracking - basic", "[JSNormalizer]")
{
    auto tester = default_config;

    SECTION("Global only")
    {
        tester.test_function_scopes({{ "", "", {FuncType::NOT_FUNC}}});
    }
    SECTION("General function call")
    {
        SECTION("in arguments")
        {
            tester.test_function_scopes({
                {"general(", "var_0000(", {FuncType::NOT_FUNC, FuncType::GENERAL}}
            });
        }
        SECTION("separated identifier and call")
        {
            tester.test_function_scopes({
                {"general  /*comment*/  (", "var_0000(", {FuncType::NOT_FUNC, FuncType::GENERAL}}
            });
        }
        SECTION("complete call")
        {
            tester.test_function_scopes({
                {"general('%62%61%72')", "var_0000('%62%61%72')", {FuncType::NOT_FUNC}}
            });
        }
        SECTION("as named function definition")
        {
            tester.test_function_scopes({
                {"general(){", "var_0000(){", {FuncType::NOT_FUNC, FuncType::NOT_FUNC}}
            });
        }
        SECTION("after defined function identifier")
        {
            tester.test_function_scopes({
                {"unescape;hello(", "unescape;var_0000(", {FuncType::NOT_FUNC, FuncType::GENERAL}}
            });
        }
        SECTION("fake defined function identifier")
        {
            tester.test_function_scopes({
                {"fake_unescape(", "var_0000(", {FuncType::NOT_FUNC, FuncType::GENERAL}}
            });
        }
        SECTION("ignored fake defined function identifier")
        {
            const std::unordered_set<std::string> s_ignored_ids_fake {"fake_unescape"};
            auto tester_fake = tester.derive({ignored_ids_list(s_ignored_ids_fake)});
            tester_fake.test_function_scopes({
                {"fake_unescape(", "fake_unescape(", {FuncType::NOT_FUNC, FuncType::GENERAL}}
            });
        }
        SECTION("as a template literal substitution")
        {
            tester.test_function_scopes({
                {"`unescape ${general(", "`unescape ${var_0000(",
                {FuncType::NOT_FUNC, FuncType::NOT_FUNC, FuncType::GENERAL}}
            });
        }
    }
    SECTION("unescape function call")
    {
        SECTION("in arguments")
        {
            tester.test_function_scopes({
                {"unescape(", "", {FuncType::NOT_FUNC, FuncType::UNESCAPE}}
            });
        }
        SECTION("separated identifier and call")
        {
            tester.test_function_scopes({
                {"unescape  /*comment*/  (", "", {FuncType::NOT_FUNC, FuncType::UNESCAPE}}
            });
        }
        SECTION("complete call")
        {
            tester.test_function_scopes({
                {"unescape('%62%61%72')", "'bar'", {FuncType::NOT_FUNC}}
            });
        }
        SECTION("as named function definition")
        {
            tester.test_function_scopes({
                {"function unescape(){", "function unescape(){",
                {FuncType::NOT_FUNC, FuncType::NOT_FUNC}}
            });
        }
        SECTION("after assignment substitution")
        {
            tester.test_function_scopes({
                {"var a = unescape; a(", "var var_0000=unescape;",
                {FuncType::NOT_FUNC, FuncType::UNESCAPE}}
            });
        }
        SECTION("literal")
        {
            tester.test_function_scopes({
                {"`unescape(", "`unescape(", {FuncType::NOT_FUNC}}
            });
        }
        SECTION("as a template literal substitution")
        {
            tester.test_function_scopes({
                {"`literal ${unescape(", "`literal ${",
                {FuncType::NOT_FUNC, FuncType::NOT_FUNC, FuncType::UNESCAPE}}
            });
        }
    }
    SECTION("decodeURI function call")
    {
        SECTION("in arguments")
        {
            tester.test_function_scopes({
                {"decodeURI(", "", {FuncType::NOT_FUNC, FuncType::UNESCAPE}}
            });
        }
        SECTION("separated identifier and call")
        {
            tester.test_function_scopes({
                {"decodeURI  /*comment*/  (", "",
                {FuncType::NOT_FUNC, FuncType::UNESCAPE}}
            });
        }
        SECTION("complete call")
        {
            tester.test_function_scopes({
                {"decodeURI('%62%61%72')", "'bar'", {FuncType::NOT_FUNC}}
            });
        }
        SECTION("as named function definition")
        {
            tester.test_function_scopes({
                {"function decodeURI(){", "function decodeURI(){",
                {FuncType::NOT_FUNC, FuncType::NOT_FUNC}}
            });
        }
        SECTION("after assignment substitution")
        {
            tester.test_function_scopes({
                {"var a = decodeURI; a(", "var var_0000=decodeURI;",
                {FuncType::NOT_FUNC, FuncType::UNESCAPE}}
            });
        }
        SECTION("literal")
        {
            tester.test_function_scopes({
                {"`decodeURI(", "`decodeURI(", {FuncType::NOT_FUNC}}
            });
        }
        SECTION("as a template literal substitution")
        {
            tester.test_function_scopes({
                {"`literal ${decodeURI(", "`literal ${",
                {FuncType::NOT_FUNC, FuncType::NOT_FUNC, FuncType::UNESCAPE}}
            });
        }
    }
    SECTION("decodeURIComponent function call")
    {
        SECTION("in arguments")
        {
            tester.test_function_scopes({
                {"decodeURIComponent(", "",
                {FuncType::NOT_FUNC, FuncType::UNESCAPE}}
            });
        }
        SECTION("separated identifier and call")
        {
            tester.test_function_scopes({
                {"decodeURIComponent  /*comment*/  (", "",
                {FuncType::NOT_FUNC, FuncType::UNESCAPE}}
            });
        }
        SECTION("complete call")
        {
            tester.test_function_scopes({
                {"decodeURIComponent('%62%61%72')", "'bar'",
                {FuncType::NOT_FUNC}}
            });
        }
        SECTION("as named function definition")
        {
            tester.test_function_scopes({
                {"function decodeURIComponent(){", "function decodeURIComponent(){",
                {FuncType::NOT_FUNC, FuncType::NOT_FUNC}}
            });
        }
        SECTION("after assignment substitution")
        {
            tester.test_function_scopes({
                {"var a = decodeURIComponent; a(", "var var_0000=decodeURIComponent;",
                {FuncType::NOT_FUNC, FuncType::UNESCAPE}}
            });
        }
        SECTION("literal")
        {
            tester.test_function_scopes({
                {"`decodeURIComponent(", "`decodeURIComponent(", {FuncType::NOT_FUNC}}
            });
        }
        SECTION("as a template literal substitution")
        {
            tester.test_function_scopes({
                {"`literal ${decodeURIComponent(", "`literal ${",
                {FuncType::NOT_FUNC, FuncType::NOT_FUNC, FuncType::UNESCAPE}}
            });
        }
    }
    SECTION("String.fromCharCode method call")
    {
        SECTION("in arguments")
        {
            tester.test_function_scopes({
                {"String.fromCharCode(", "'",
                {FuncType::NOT_FUNC, FuncType::CHAR_CODE}}
            });
        }
        SECTION("separated identifier and call")
        {
            tester.test_function_scopes({
                {"String.fromCharCode  /*comment*/  (", "'",
                {FuncType::NOT_FUNC, FuncType::CHAR_CODE}}
            });
        }
        SECTION("complete call")
        {
            tester.test_function_scopes({
                {"String.fromCharCode( 65, 0x42 )", "'AB'",
                {FuncType::NOT_FUNC}}
            });
        }
        SECTION("as named function definition")
        {
            tester.test_function_scopes({
                {"function String.fromCharCode(){", "function String.fromCharCode(){",
                {FuncType::NOT_FUNC, FuncType::NOT_FUNC}}
            });
        }
        SECTION("after class name assignment substitution")
        {
            tester.test_function_scopes({
                {"var a = String; a.fromCharCode(", "var var_0000=String;'",
                {FuncType::NOT_FUNC, FuncType::CHAR_CODE}}
            });
        }
        SECTION("after assignment substitution")
        {
            tester.test_function_scopes({
                {"var a = String.fromCharCode; a(",
                "var var_0000=String.fromCharCode;'",
                {FuncType::NOT_FUNC, FuncType::CHAR_CODE}}
            });
        }
        SECTION("not a Sting class member call")
        {
            tester.test_function_scopes({
                {"fromCharCode(",
                "var_0000(",
                {FuncType::NOT_FUNC, FuncType::GENERAL}}
            });
        }
        SECTION("literal")
        {
            tester.test_function_scopes({
                {"`String.fromCharCode(", "`String.fromCharCode(", {FuncType::NOT_FUNC}}
            });
        }
        SECTION("as a template literal substitution")
        {
            tester.test_function_scopes({
                {"`literal ${String.fromCharCode(", "`literal ${'",
                {FuncType::NOT_FUNC, FuncType::NOT_FUNC, FuncType::CHAR_CODE}}
            });
        }
    }
}

TEST_CASE("Function call tracking - nesting", "[JSNormalizer]")
{
   auto tester = default_config; 

    SECTION("Opening")
    {
        SECTION("Multiple general functions")
        {
            tester.test_function_scopes({
                { "general( general( general(", "var_0000(var_0000(var_0000(",
                {FuncType::NOT_FUNC, FuncType::GENERAL, FuncType::GENERAL, FuncType::GENERAL}}
            },
            {check_unescape_nesting(false)});
        }
        SECTION("Multiple unescape functions")
        {
            tester.test_function_scopes({
                {"unescape( unescape( unescape(", "",
                {FuncType::NOT_FUNC, FuncType::UNESCAPE, FuncType::UNESCAPE, FuncType::UNESCAPE}}
            },
            {check_unescape_nesting(true)});
        }
        SECTION("Multiple different unescape functions")
        {
            tester.test_function_scopes({
                {"unescape( decodeURI( decodeURIComponent(", "",
                {FuncType::NOT_FUNC, FuncType::UNESCAPE, FuncType::UNESCAPE, FuncType::UNESCAPE}}
            },
            {check_unescape_nesting(true)});
        }
        SECTION("Multiple String.fromCharCode functions")
        {
            tester.test_function_scopes({
                {"String.fromCharCode( String.fromCharCode( String.fromCharCode(", "'' '' '",
                {FuncType::NOT_FUNC, FuncType::CHAR_CODE, FuncType::CHAR_CODE, FuncType::CHAR_CODE}}
            },
            {check_unescape_nesting(false)});
        }
        SECTION("Mixed function calls")
        {
            tester.test_function_scopes({
                {"general( unescape( String.fromCharCode(", "var_0000('",
                {FuncType::NOT_FUNC, FuncType::GENERAL, FuncType::UNESCAPE, FuncType::CHAR_CODE}}
            },
            {check_unescape_nesting(false)});
        }
    }
    SECTION("Closing")
    {
        SECTION("Multiple general functions")
        {
            tester.test_function_scopes({
                {"general( general( general( a ) )", "var_0000(var_0000(var_0000(var_0001))",
                {FuncType::NOT_FUNC, FuncType::GENERAL}}
            });
        }
        SECTION("Multiple unescape functions")
        {
            tester.test_function_scopes({
                {"unescape( unescape( unescape( '%62%61%72' ) )", "'bar'",
                {FuncType::NOT_FUNC, FuncType::UNESCAPE }}
            });
        }
        SECTION("Multiple different unescape functions")
        {
            tester.test_function_scopes({
                {"unescape( decodeURI( decodeURIComponent( '%62%61%72' ) )", "'bar'",
                {FuncType::NOT_FUNC, FuncType::UNESCAPE }}
            });
        }
        SECTION("Multiple String.fromCharCode methods")
        {
            tester.test_function_scopes({
                {"String.fromCharCode( String.fromCharCode( String.fromCharCode( 65, 0x42 ) )",
                "'' '' 'AB'",
                {FuncType::NOT_FUNC, FuncType::CHAR_CODE}}
            });
        }
        SECTION("Mixed function calls")
        {
            tester.test_function_scopes({
                {"general( unescape( String.fromCharCode( 65, 0x42 ) )",
                "var_0000('AB'",
                {FuncType::NOT_FUNC, FuncType::GENERAL}}
            });
        }
    }
}

TEST_CASE("Function call tracking - over multiple PDU", "[JSNormalizer]")
{
    auto tester = default_config;
    SECTION("split in the middle of the identifier")
    {
        tester.test_function_scopes({
            {"un",          "var_0000",     {FuncType::NOT_FUNC}},
            {"escape",      "unescape",     {FuncType::NOT_FUNC}},
            {"(",           "",             {FuncType::NOT_FUNC,
                                             FuncType::UNESCAPE}},
            {")",           "",             {FuncType::NOT_FUNC}},
        });
    }
    SECTION("split between identifier and parenthesis")
    {
        tester.test_function_scopes({
            {"decodeURI",   "decodeURI",    {FuncType::NOT_FUNC}},
            {"(",           "",             {FuncType::NOT_FUNC,
                                             FuncType::UNESCAPE}},
            {")",           "",             {FuncType::NOT_FUNC}},
        });
    }
    SECTION("comment between identifier and parenthesis")
    {
        tester.test_function_scopes({
            {"unescape",                "unescape",     {FuncType::NOT_FUNC}},
            {"//String.fromCharCode\n", "unescape",     {FuncType::NOT_FUNC}},
            {"(",                       "",             {FuncType::NOT_FUNC,
                                                         FuncType::UNESCAPE}},
            {")",                       "",             {FuncType::NOT_FUNC}},
        });
    }
    SECTION("split in arguments")
    {
        tester.test_function_scopes({
            {"general",         "var_0000",                         {FuncType::NOT_FUNC}},
            {"(",               "var_0000(",                        {FuncType::NOT_FUNC,
                                                                     FuncType::GENERAL}},
            {"a",               "var_0000(var_0001",                {FuncType::NOT_FUNC,
                                                                     FuncType::GENERAL}},
            {"+ b",             "var_0000(var_0001+var_0002",       {FuncType::NOT_FUNC,
                                                                     FuncType::GENERAL}},
            {")",               "var_0000(var_0001+var_0002)",      {FuncType::NOT_FUNC}},
        });
    }
    SECTION("literal in arguments")
    {
        tester.test_function_scopes({
            {"String",          "String",                               {FuncType::NOT_FUNC}},
            {".fromCharCode",   "String.fromCharCode",                  {FuncType::NOT_FUNC}},
            {"(`",              "'' `",                                 {FuncType::NOT_FUNC,
                                                                         FuncType::CHAR_CODE}},
            {"un",              "'' `un",                               {FuncType::NOT_FUNC,
                                                                         FuncType::CHAR_CODE}},
            {"escape(",         "'' `unescape(",                        {FuncType::NOT_FUNC,
                                                                         FuncType::CHAR_CODE}},
            {"`)",              "'' `unescape(`",                       {FuncType::NOT_FUNC}},
        });
    }
    SECTION("Nesting - Mixed function calls")
    {
        tester.test_function_scopes({
            {"decode",                      "var_0000",                 {FuncType::NOT_FUNC}},
            {"URI",                         "decodeURI",                {FuncType::NOT_FUNC}},
            {"Component",                   "decodeURIComponent",       {FuncType::NOT_FUNC}},
            {"(",                           "",                         {FuncType::NOT_FUNC,
                                                                         FuncType::UNESCAPE}},
            {" a, ",                        "var_0001,",
                                                                        {FuncType::NOT_FUNC,
                                                                         FuncType::UNESCAPE}},
            {" String.fromCharCode( ar",    "var_0001,'' var_0002",
                                                                        {FuncType::NOT_FUNC,
                                                                         FuncType::UNESCAPE,
                                                                         FuncType::CHAR_CODE}},

            {"g ), b, foo",                 "var_0001,'' var_0003,var_0004,var_0005",
                                                                        {FuncType::NOT_FUNC,
                                                                         FuncType::UNESCAPE}},

            {"bar( ",                       "var_0001,'' var_0003,var_0004,var_0006(",
                                                                        {FuncType::NOT_FUNC,
                                                                         FuncType::UNESCAPE,
                                                                         FuncType::GENERAL}},

            {"))",                          "var_0001,'' var_0003,var_0004,var_0006()",
                                                                        {FuncType::NOT_FUNC}}
        });
    }
}

TEST_CASE("String Concatenation - Basic", "[JSNormalizer]")
{
    SECTION("Two strings")
    {
        SECTION("single quoted strings")
            test_normalization("'foo' + 'bar'", "'foobar'");

        SECTION("double quoted strings")
            test_normalization("\"foo\" + \"bar\"", "\"foobar\"");

        SECTION("double quoted string + single quoted string")
            test_normalization("\"foo\" + 'bar'", "\"foobar'");

        SECTION("single quoted string + double quoted string")
            test_normalization("'foo' + \"bar\"", "'foobar\"");

        SECTION("string + function call")
            test_normalization("'foo' + general('bar')", "'foo'+var_0000('bar')");

        SECTION("function call + string")
            test_normalization("general('bar') + 'foo'", "var_0000('bar')+'foo'");

        SECTION("inside function call arguments")
            test_normalization("general('foo' + 'bar')", "var_0000('foobar')");

        SECTION("with concatenation inside")
            test_normalization("'\"foo\"' + '+\"bar\"')", "'\"foo\"+\"bar\"'");

        SECTION("terminated concatenation")
            test_normalization("'foo' + '!</script>')", "'foo!");
    }
    SECTION("Three strings")
    {
        SECTION("single quoted strings")
            test_normalization("'foo' + 'bar' + 'baz'", "'foobarbaz'");

        SECTION("double quoted strings")
            test_normalization("\"foo\" + \"bar\" + \"baz\"", "\"foobarbaz\"");

        SECTION("single quoted string + double quoted string + double quoted string")
            test_normalization("'foo' + \"bar\" + \"baz\"", "'foobarbaz\"");

        SECTION("double quoted string + double quoted string + single quoted string")
            test_normalization("\"foo\" + \"bar\" + 'baz'", "\"foobarbaz'");

        SECTION("double quoted string + single quoted string + double quoted string")
            test_normalization("\"foo\" + 'bar' + \"baz\"", "\"foobarbaz\"");

        SECTION("function call between literals")
            test_normalization("'foo' + general('bar') + \"baz\"", "'foo'+var_0000('bar')+\"baz\"");
    }
    SECTION("multiline comment before the plus symbol")
        test_normalization("'foo' /*comment*/ + 'bar'", "'foobar'");

    SECTION("single line comment before the plus symbol")
        test_normalization("'foo' //comment\n + 'bar'", "'foobar'");

    SECTION("HTML comment before the plus symbol")
        test_normalization("'foo' <!-- HTML comment\n + 'bar'", "'foobar'");

    SECTION("tab after the plus symbol")
        test_normalization("'foo' + \t 'bar'", "'foobar'");

    SECTION("comment after the plus symbol")
        test_normalization("'foo' + /*comment*/ 'bar'", "'foobar'");

    SECTION("with a non-string literal in chain")
        test_normalization("'foo' + 'bar' + 2", "'foobar'+2");

    SECTION("with a non-string literal between strings")
        test_normalization("'foo' + 2 + 'bar'", "'foo'+2+'bar'");

    SECTION("with a template literal")
        test_normalization("\"foo\" + `bar`", "\"foo\"+`bar`");

    SECTION("with a template literal substitution")
        test_normalization("\"foo\" + `bar${a + 1}`", "\"foo\"+`bar${var_0000+1}`");

    SECTION("inside a template literal substitution")
        test_normalization("`literal${\"foo\" + \"bar\"}`", "`literal${\"foobar\"}`");

    SECTION("automatic semicolon insertion after concatenation")
        test_normalization("'foo' + 'bar'\nvar a = 5;", "'foobar';var var_0000=5;");
}

TEST_CASE("String Concatenation - With unescape", "[JSNormalizer]")
{
    SECTION("unescape")
    {
        SECTION("single quoted string + single quoted unescape")
            test_normalization("'foo' + unescape('%62%61%72')", "'foobar'");

        SECTION("double quoted string + single quoted unescape")
            test_normalization("\"foo\" + unescape('%62%61%72')", "\"foobar'");

        SECTION("single quoted unescape + single quoted string")
            test_normalization("unescape('%66%6f%6f') + 'bar'", "'foobar'");

        SECTION("double quoted unescape + double quoted string")
            test_normalization("unescape(\"%66%6f%6f\") + \"bar\"", "\"foobar\"");

        SECTION("string + unescape + string")
            test_normalization("'foo' + unescape('%62%61%72') + 'baz'", "'foobarbaz'");

        SECTION("unescape + unescape")
            test_normalization("unescape('%66%6f%6f') + unescape('%62%61%72')", "'foobar'");

        SECTION("inside function call arguments")
            test_normalization("unescape('foo' + '%62' + '%61' + '%72')", "'foobar'");

        SECTION("Latin-1 encoding - string + unescape")
            test_normalization("'foo ' + unescape('%eb')", "'foo \xEB'");

        SECTION("Latin-1 encoding - unescape + string")
            test_normalization("unescape('%eb') + ' foo'", "'\xEB foo'");

        SECTION("Latin-1 encoding - unescape + unescape")
            test_normalization("unescape('%eb') + unescape('%eb')", "'\xEB\xEB'");
    }
    SECTION("String.fromCharCode")
    {
        SECTION("single quoted string + String.fromCharCode")
            test_normalization("'foo' + String.fromCharCode(98, 97, 114)", "'foobar'");

        SECTION("double quoted string + String.fromCharCode")
            test_normalization("\"foo\" + String.fromCharCode(98, 97, 114)", "\"foobar'");

        SECTION("String.fromCharCode + single quoted string")
            test_normalization("String.fromCharCode(102, 111, 111) + 'bar'", "'foobar'");

        SECTION("String.fromCharCode + double quoted string")
            test_normalization("String.fromCharCode(102, 111, 111) + \"bar\"", "'foobar\"");
        SECTION("Inside function call arguments")
            test_normalization(" String.fromCharCode('foo' + 'bar')", "'' 'foobar'");
    }
}

TEST_CASE("String Concatenation - Multiple PDU", "[JSNormalizer]")
{
    SECTION("Two single quoted strings")
    {
        test_normalization({
            {"'",   "'"         },
            {"foo", "'foo"      },
            {"'",   "'foo'"     },
            {" +",  "'foo'+"    },
            {" '",  "'foo"      },
            {"bar", "'foobar"   },
            {"'",   "'foobar'"  }
        });
    }
    SECTION("Three double quoted strings")
    {
        test_normalization({
            {"\"foo",       "\"foo"         },
            {"\" + \"",     "\"foo"         },
            {"bar\"",       "\"foobar\""    },
            {"+ \"baz\"",   "\"foobarbaz\"" }

        });
    }
    SECTION("single quoted string + double quoted string")
    {
        test_normalization({
            {"'foo",    "'foo"      },
            {"'",       "'foo'"     },
            {" + \"",   "\'foo"     },
            {"bar",     "'foobar"   },
            {"\"",      "'foobar\"" }
        });
    }
    SECTION("With a non-string literal between strings")
    {
        test_normalization({
            {"\"fo",    "\"fo"                  },
            {"o\"",     "\"foo\""               },
            {" + i",    "\"foo\"+var_0000"      },
            {"d + ",    "\"foo\"+var_0001+"     },
            {"'ba",     "\"foo\"+var_0001+'ba"  },
            {"r'",      "\"foo\"+var_0001+'bar'"}
        });
    }
    SECTION("With unescape")
    {
        test_normalization({
            {"'fo",         "'fo"               },
            {"o'",          "'foo'"             },
            {" + ",         "'foo'+"            },
            {"unescape",    "'foo'+unescape"    },
            {"(",           "'foo'+"            },
            {"'%62%61%72",  "'foobar"           },
            {"'+",          "'foobar'+"         },
            {"'baz",        "'foobarbaz"        },
            {"'",           "'foobarbaz'"       }
        });
    }
    SECTION("With String.fromCharCode")
    {
        test_normalization({
            {"'foo",            "'foo"                      },
            {"' + ",            "'foo'+"                    },
            {"String",          "'foo'+String"              },
            {".fromCharCode",   "'foo'+String.fromCharCode" },
            {"(",               "'foo"                      },
            {"98,97,114",       "'foobar"                   },
            {")+",              "'foobar'+"                 },
            {"'",               "'foobar"                   },
            {"baz'",            "'foobarbaz'"               }
        });
    }
}

#endif

