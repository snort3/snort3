//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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

#include "catch/catch.hpp"

#include <cstring>

#include "utils/js_normalizer.h"

namespace snort
{
// Mock for JSTokenizer
[[noreturn]] void FatalError(const char*, ...)
{ exit(EXIT_FAILURE); }
}

using namespace snort;

#define NORM_DEPTH 65535

#define NORMALIZE(srcbuf, expected)                                        \
    char dstbuf[sizeof(expected)];                                         \
    int bytes_copied;                                                      \
    const char* ptr = srcbuf;                                              \
    JSNormState state;                                                     \
    state.norm_depth = NORM_DEPTH;                                         \
    state.alerts = 0;                                                      \
    int ret = JSNormalizer::normalize(srcbuf, sizeof(srcbuf),              \
        dstbuf, sizeof(dstbuf), &ptr, &bytes_copied, state);

#define VALIDATE(srcbuf, expected)                    \
    CHECK(ret == 0);                                  \
    CHECK((ptr - srcbuf) == sizeof(srcbuf));          \
    CHECK(bytes_copied == sizeof(expected) - 1);      \
    CHECK(!memcmp(dstbuf, expected, bytes_copied));

#define VALIDATE_FAIL(srcbuf, expected, ret_code, ptr_offset)      \
    CHECK(ret == ret_code);                                        \
    CHECK((ptr - srcbuf) == ptr_offset);                           \
    CHECK(bytes_copied == sizeof(expected) - 1);                   \
    CHECK(!memcmp(dstbuf, expected, bytes_copied));

#define VALIDATE_ALERT(alert)       \
    CHECK(state.alerts & alert);

// ClamAV test cases
static const char clamav_buf0[] =
    "function foo(a, b) {\n"
    "var x = 1.9e2*2*a/ 4.;\n"
    "var y = 'test\\'tst';//var\n"
    "x=b[5],/* multiline\nvar z=6;\nsome*some/other**/"
    "z=x/y;/* multiline oneline */var t=z/a;\n"
    "z=[test,testi];"
    "document.writeln('something\\n');}";

static const char clamav_expected0[] =
    "function foo(a,b){var x=1.9e2*2*a/4.;var y='test\\'tst';x=b[5],z=x/y;var t=z/a;"
    "z=[test,testi];document.writeln('something\\n');}";

static const char clamav_buf1[] =
    "function () { var id\\u1234tx;}";

static const char clamav_expected1[] =
    "function(){var id\u1234tx;}";

static const char clamav_buf2[] =
    "function () { var tst=\"a\"+'bc'+     'd'; }";

static const char clamav_expected2[] =
    "function(){var tst=\"a\"+'bc'+'d';}";

static const char clamav_buf3[] =
    "dF('bmfsu%2639%2638x11u%2638%263%3A%264C1');";

static const char clamav_expected3[] =
    "dF('bmfsu%2639%2638x11u%2638%263%3A%264C1');";

#define B64 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

static char clamav_buf4[] =
    "qbphzrag.jevgr(harfpncr('%3P%73%63%72%69%70%74%20%6P%61%6R%67%75%61%67%65%3Q%22%6N%61%76%61"
        "%73%63%72%69%70%74%22%3R%66%75%6R%63%74%69%6S%6R%20%64%46%28%73%29%7O%76%61%72%20%73%31"
        "%3Q%75%6R%65%73%63%61%70%65%28%73%2R%73%75%62%73%74%72%28%30%2P%73%2R%6P%65%6R%67%74%68"
        "%2Q%31%29%29%3O%20%76%61%72%20%74%3Q%27%27%3O%66%6S%72%28%69%3Q%30%3O%69%3P%73%31%2R%6P"
        "%65%6R%67%74%68%3O%69%2O%2O%29%74%2O%3Q%53%74%72%69%6R%67%2R%66%72%6S%6Q%43%68%61%72%43"
        "%6S%64%65%28%73%31%2R%63%68%61%72%43%6S%64%65%41%74%28%69%29%2Q%73%2R%73%75%62%73%74%72"
        "%28%73%2R%6P%65%6R%67%74%68%2Q%31%2P%31%29%29%3O%64%6S%63%75%6Q%65%6R%74%2R%77%72%69%74"
        "%65%28%75%6R%65%73%63%61%70%65%28%74%29%29%3O%7Q%3P%2S%73%63%72%69%70%74%3R'));"
        "riny(qS('tV%285%3O%285%3Nsdwjl%28585%3N7%28586Q%28585%3N7%3P%7P55l%28585%3N7%3P%28585%3N7"
        "%28586R%28585%3N8T5%285%3N%285%3P%286R3'));";

static char clamav_expected4[] =
    "qbphzrag.jevgr(harfpncr('%3P%73%63%72%69%70%74%20%6P%61%6R%67%75%61%67%65%3Q%22%6N%61%76%61"
        "%73%63%72%69%70%74%22%3R%66%75%6R%63%74%69%6S%6R%20%64%46%28%73%29%7O%76%61%72%20%73%31"
        "%3Q%75%6R%65%73%63%61%70%65%28%73%2R%73%75%62%73%74%72%28%30%2P%73%2R%6P%65%6R%67%74%68"
        "%2Q%31%29%29%3O%20%76%61%72%20%74%3Q%27%27%3O%66%6S%72%28%69%3Q%30%3O%69%3P%73%31%2R%6P"
        "%65%6R%67%74%68%3O%69%2O%2O%29%74%2O%3Q%53%74%72%69%6R%67%2R%66%72%6S%6Q%43%68%61%72%43"
        "%6S%64%65%28%73%31%2R%63%68%61%72%43%6S%64%65%41%74%28%69%29%2Q%73%2R%73%75%62%73%74%72"
        "%28%73%2R%6P%65%6R%67%74%68%2Q%31%2P%31%29%29%3O%64%6S%63%75%6Q%65%6R%74%2R%77%72%69%74"
        "%65%28%75%6R%65%73%63%61%70%65%28%74%29%29%3O%7Q%3P%2S%73%63%72%69%70%74%3R'));"
        "riny(qS('tV%285%3O%285%3Nsdwjl%28585%3N7%28586Q%28585%3N7%3P%7P55l%28585%3N7%3P%28585%3N7"
        "%28586R%28585%3N8T5%285%3N%285%3P%286R3'));";

static char clamav_buf5[] =
    "shapgvba (c,n,p,x,r,e){}('0(\\'1\\');',2,2,'nyreg|j00g'.fcyvg('|'),0,{});";

static const char clamav_expected5[] =
    "shapgvba(c,n,p,x,r,e){}('0(\\'1\\');',2,2,'nyreg|j00g'.fcyvg('|'),0,{});";

static const char clamav_buf6[] =
    "function $(p,a,c,k,e,d){} something(); $('0(\\'1\\');',2,2,'alert|w00t'.split('|'),0,{});";

static const char clamav_expected6[] =
    "function $(p,a,c,k,e,d){}something();$('0(\\'1\\');',2,2,'alert|w00t'.split('|'),0,{});";

static const char clamav_buf7[] =
    "var z=\"tst" B64 "tst\";";

static const char clamav_expected7[] =
    "var z=\"tst" B64 "tst\";";

static const char clamav_buf8[] =
    "var z=\'tst" B64 "tst\';";

static const char clamav_expected8[] =
    "var z=\'tst" B64 "tst\';";

static char clamav_buf9[] =
    "riny(harfpncr('%61%6p%65%72%74%28%27%74%65%73%74%27%29%3o'));";

static const char clamav_expected9[] =
    "riny(harfpncr('%61%6p%65%72%74%28%27%74%65%73%74%27%29%3o'));";

static const char clamav_buf10[] =
    "function $ $() dF(x); function (p,a,c,k,e,r){function $(){}";

static const char clamav_expected10[] =
    "function $ $()dF(x);function(p,a,c,k,e,r){function $(){}";

static const char clamav_buf11[] =
    "var x=123456789 ;";

static const char clamav_expected11[] =
    "var x=123456789;";

static const char clamav_buf12[] =
    "var x='test\\u0000test';";

static const char clamav_expected12[] =
    "var x='test\\u0000test';";

static const char clamav_buf13[] =
    "var x\\s12345";

static const char clamav_expected13[] =
    "var x\\s12345";

static const char clamav_buf14[] =
    "document.write(unescape('test%20test";

static const char clamav_expected14[] =
    "document.write(unescape('test%20test";

TEST_CASE("clamav tests", "[JSNormalizer]")
{
    SECTION("test_case_0")
    {
        NORMALIZE(clamav_buf0, clamav_expected0);
        VALIDATE(clamav_buf0, clamav_expected0);
    }
    SECTION("test_case_1")
    {
        NORMALIZE(clamav_buf1, clamav_expected1);
        VALIDATE(clamav_buf1, clamav_expected1);
    }
    SECTION("test_case_2")
    {
        NORMALIZE(clamav_buf2, clamav_expected2);
        VALIDATE(clamav_buf2, clamav_expected2);
    }
    SECTION("test_case_3")
    {
        NORMALIZE(clamav_buf3, clamav_expected3);
        VALIDATE(clamav_buf3, clamav_expected3);
    }
    SECTION("test_case_4")
    {
        NORMALIZE(clamav_buf4, clamav_expected4);
        VALIDATE(clamav_buf4, clamav_expected4);
    }
    SECTION("test_case_5")
    {
        NORMALIZE(clamav_buf5, clamav_expected5);
        VALIDATE(clamav_buf5, clamav_expected5);
    }
    SECTION("test_case_6")
    {
        NORMALIZE(clamav_buf6, clamav_expected6);
        VALIDATE(clamav_buf6, clamav_expected6);
    }
    SECTION("test_case_7")
    {
        NORMALIZE(clamav_buf7, clamav_expected7);
        VALIDATE(clamav_buf7, clamav_expected7);
    }
    SECTION("test_case_8")
    {
        NORMALIZE(clamav_buf8, clamav_expected8);
        VALIDATE(clamav_buf8, clamav_expected8);
    }
    SECTION("test_case_9")
    {
        NORMALIZE(clamav_buf9, clamav_expected9);
        VALIDATE(clamav_buf9, clamav_expected9);
    }
    SECTION("test_case_10")
    {
        NORMALIZE(clamav_buf10, clamav_expected10);
        VALIDATE(clamav_buf10, clamav_expected10);
    }
    SECTION("test_case_11")
    {
        NORMALIZE(clamav_buf11, clamav_expected11);
        VALIDATE(clamav_buf11, clamav_expected11);
    }
    SECTION("test_case_12")
    {
        NORMALIZE(clamav_buf12, clamav_expected12);
        VALIDATE(clamav_buf12, clamav_expected12);
    }
    SECTION("test_case_13")
    {
        NORMALIZE(clamav_buf13, clamav_expected13);
        VALIDATE(clamav_buf13, clamav_expected13);
    }
    SECTION("test_case_14")
    {
        NORMALIZE(clamav_buf14, clamav_expected14);
        VALIDATE(clamav_buf14, clamav_expected14);
    }
}

// Test cases for all match patterns
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
    "implements static instanceof new this class let typeof var with enum private catch "
    "continue default extends public finally for if super yield return switch throw const "
    "interface void while delete export package";

static const char all_patterns_expected3[] =
    "break case debugger in import protected do else function try "
    "implements static instanceof new this class let typeof var with enum private catch "
    "continue default extends public finally for if super yield return switch throw const "
    "interface void while delete export package";

static const char all_patterns_buf4[] =
    "/regex/g undefined null true false 2 23 2.3 2.23 .2 .02 4. +2 -2 "
    "+3.3 -3.3 +23 -32 2.3E45 3.E34 -2.3E45 -3.E34 +2.3E45 +3.E34 0x1234 0XFFFF Infinity "
    "\xE2\x88\x9E NaN \"\" \"double string\" \"d\" '' 'single string' 's' x=/regex/gs "
    "x=2/2/1";

static const char all_patterns_expected4[] =
    "/regex/g undefined null true false 2 23 2.3 2.23 .2 .02 4.+2-2"
    "+3.3-3.3+23-32 2.3E45 3.E34-2.3E45-3.E34+2.3E45+3.E34 0x1234 0XFFFF Infinity "
    "\xE2\x88\x9E NaN \"\" \"double string\" \"d\" '' 'single string' 's' x=/regex/gs "
    "x=2/2/1";

static const char all_patterns_buf5[] =
    "$2abc _2abc abc $__$ 肖晗 XÆA12 \\u0041abc \\u00FBdef \\u1234ghi ab\xE2\x80\xA8ww "
    "ab\xE2\x80\xA9ww ab\xEF\xBB\xBFww ab∞ww 2abc";

static const char all_patterns_expected5[] =
    "$2abc _2abc abc $__$ 肖晗 XÆA12 \u0041abc \u00FBdef \u1234ghi ab ww "
    "ab ww ab ww ab ∞ ww 2 abc";

TEST_CASE("all patterns", "[JSNormalizer]")
{
    SECTION("whitespaces and special characters")
    {
        NORMALIZE(all_patterns_buf0, all_patterns_expected0);
        VALIDATE(all_patterns_buf0, all_patterns_expected0);
    }
    SECTION("comments")
    {
        NORMALIZE(all_patterns_buf1, all_patterns_expected1);
        VALIDATE(all_patterns_buf1, all_patterns_expected1);
    }
    SECTION("directives")
    {
        const char srcbuf0[] = "'use strict'\nvar a = 1;";
        const char srcbuf1[] = "\"use strict\"\nvar a = 1;";
        const char srcbuf2[] = "'use strict';var a = 1;";
        const char srcbuf3[] = "\"use strict\";var a = 1;";
        const char srcbuf4[] = "var a = 1 'use strict';";
        const char expected0[] = "'use strict';var a=1;";
        const char expected1[] = "\"use strict\";var a=1;";
        const char expected2[] = "var a=1 'use strict';";
        char dstbuf0[sizeof(expected0)];
        char dstbuf1[sizeof(expected1)];
        char dstbuf2[sizeof(expected0)];
        char dstbuf3[sizeof(expected1)];
        char dstbuf4[sizeof(expected2)];
        int bytes_copied0, bytes_copied1, bytes_copied2, bytes_copied3, bytes_copied4;
        const char* ptr0 = srcbuf0;
        const char* ptr1 = srcbuf1;
        const char* ptr2 = srcbuf2;
        const char* ptr3 = srcbuf3;
        const char* ptr4 = srcbuf4;
        JSNormState state;
        state.norm_depth = NORM_DEPTH;
        state.alerts = 0;

        int ret0 = JSNormalizer::normalize(srcbuf0, sizeof(srcbuf0), dstbuf0, sizeof(dstbuf0),
            &ptr0, &bytes_copied0, state);
        int ret1 = JSNormalizer::normalize(srcbuf1, sizeof(srcbuf1), dstbuf1, sizeof(dstbuf1),
            &ptr1, &bytes_copied1, state);
        int ret2 = JSNormalizer::normalize(srcbuf2, sizeof(srcbuf2), dstbuf2, sizeof(dstbuf2),
            &ptr2, &bytes_copied2, state);
        int ret3 = JSNormalizer::normalize(srcbuf3, sizeof(srcbuf3), dstbuf3, sizeof(dstbuf3),
            &ptr3, &bytes_copied3, state);
        int ret4 = JSNormalizer::normalize(srcbuf4, sizeof(srcbuf4), dstbuf4, sizeof(dstbuf4),
            &ptr4, &bytes_copied4, state);

        CHECK(ret0 == 0);
        CHECK((ptr0 - srcbuf0) == sizeof(srcbuf0));
        CHECK(bytes_copied0 == sizeof(expected0) - 1);
        CHECK(!memcmp(dstbuf0, expected0, bytes_copied0));

        CHECK(ret1 == 0);
        CHECK((ptr1 - srcbuf1) == sizeof(srcbuf1));
        CHECK(bytes_copied1 == sizeof(expected1) - 1);
        CHECK(!memcmp(dstbuf1, expected1, bytes_copied1));

        CHECK(ret2 == 0);
        CHECK((ptr2 - srcbuf2) == sizeof(srcbuf2));
        CHECK(bytes_copied2 == sizeof(expected0) - 1);
        CHECK(!memcmp(dstbuf2, expected0, bytes_copied2));

        CHECK(ret3 == 0);
        CHECK((ptr3 - srcbuf3) == sizeof(srcbuf3));
        CHECK(bytes_copied3 == sizeof(expected1) - 1);
        CHECK(!memcmp(dstbuf3, expected1, bytes_copied3));

        CHECK(ret4 == 0);
        CHECK((ptr4 - srcbuf4) == sizeof(srcbuf4));
        CHECK(bytes_copied4 == sizeof(expected2) - 1);
        CHECK(!memcmp(dstbuf4, expected2, bytes_copied4));
    }
    SECTION("punctuators")
    {
        NORMALIZE(all_patterns_buf2, all_patterns_expected2);
        VALIDATE(all_patterns_buf2, all_patterns_expected2);
    }
    SECTION("keywords")
    {
        NORMALIZE(all_patterns_buf3, all_patterns_expected3);
        VALIDATE(all_patterns_buf3, all_patterns_expected3);
    }
    SECTION("literals")
    {
        NORMALIZE(all_patterns_buf4, all_patterns_expected4);
        VALIDATE(all_patterns_buf4, all_patterns_expected4);
    }
    SECTION("identifiers")
    {
        NORMALIZE(all_patterns_buf5, all_patterns_expected5);
        VALIDATE(all_patterns_buf5, all_patterns_expected5);
    }
}

// Tests for different syntax cases
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
    "var a;var b=\"init this    stuff\";var c=\"Hi\"+\" \"+\"Joe\";"
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
    "document.write(i+\", \");}while(i<100)for(var i=0;i<10;i++){if(i==5){break;}"
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
    "var a=2 /ab -cd/";

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

static const char syntax_cases_buf15[] =
    "var str1 = 'abc\u2028 def' ;\n"
    "var str2 = 'abc\u2029 def' ;\n\r";

static const char syntax_cases_expected15[] =
    "var str1='abc\u2028 def';"
    "var str2='abc\u2029 def';";

static const char syntax_cases_buf16[] =
    "var invalid_str = \"abc\n def\"";

static const char syntax_cases_expected16[] =
    "var invalid_str=\"abc\"def \"";

static const char syntax_cases_buf17[] =
    "var invalid_str = 'abc\r def'";

static const char syntax_cases_expected17[] =
    "var invalid_str='abc'def '";

static const char syntax_cases_buf18[] =
    "var invalid_str = 'abc\\\n\r def'";

static const char syntax_cases_expected18[] =
    "var invalid_str='abc'def '";

static const char syntax_cases_buf19[] =
    "var invalid_re = /abc\\\n def/";

static const char syntax_cases_expected19[] =
    "var invalid_re=/abc/def/";

static const char syntax_cases_buf20[] =
    "var invalid_re = /abc\\\r\n def/";

static const char syntax_cases_expected20[] =
    "var invalid_re=/abc/def/";

TEST_CASE("syntax cases", "[JSNormalizer]")
{
    SECTION("variables")
    {
        NORMALIZE(syntax_cases_buf0, syntax_cases_expected0);
        VALIDATE(syntax_cases_buf0, syntax_cases_expected0);
    }
    SECTION("operators")
    {
        NORMALIZE(syntax_cases_buf1, syntax_cases_expected1);
        VALIDATE(syntax_cases_buf1, syntax_cases_expected1);
    }
    SECTION("arithmetic and logical operators")
    {
        NORMALIZE(syntax_cases_buf2, syntax_cases_expected2);
        VALIDATE(syntax_cases_buf2, syntax_cases_expected2);
    }
    SECTION("complex object")
    {
        NORMALIZE(syntax_cases_buf3, syntax_cases_expected3);
        VALIDATE(syntax_cases_buf3, syntax_cases_expected3);
    }
    SECTION("arrays")
    {
        NORMALIZE(syntax_cases_buf4, syntax_cases_expected4);
        VALIDATE(syntax_cases_buf4, syntax_cases_expected4);
    }
    SECTION("loops")
    {
        NORMALIZE(syntax_cases_buf5, syntax_cases_expected5);
        VALIDATE(syntax_cases_buf5, syntax_cases_expected5);
    }
    SECTION("if-else and switch statements")
    {
        NORMALIZE(syntax_cases_buf6, syntax_cases_expected6);
        VALIDATE(syntax_cases_buf6, syntax_cases_expected6);
    }
    SECTION("try-catch statements")
    {
        NORMALIZE(syntax_cases_buf7, syntax_cases_expected7);
        VALIDATE(syntax_cases_buf7, syntax_cases_expected7);
    }
    SECTION("functions and promises")
    {
        NORMALIZE(syntax_cases_buf8, syntax_cases_expected8);
        VALIDATE(syntax_cases_buf8, syntax_cases_expected8);
    }
    SECTION("regex-division ambiguity")
    {
        NORMALIZE(syntax_cases_buf9, syntax_cases_expected9);
        VALIDATE(syntax_cases_buf9, syntax_cases_expected9);
    }
    SECTION("regex on a new line")
    {
        NORMALIZE(syntax_cases_buf10, syntax_cases_expected10);
        VALIDATE(syntax_cases_buf10, syntax_cases_expected10);
    }
    SECTION("string and regex literals ambiguity with escaped sentinel chars")
    {
        NORMALIZE(syntax_cases_buf11, syntax_cases_expected11);
        VALIDATE(syntax_cases_buf11, syntax_cases_expected11);
    }
    SECTION("escaped LF and CR chars in literals")
    {
        NORMALIZE(syntax_cases_buf12, syntax_cases_expected12);
        VALIDATE(syntax_cases_buf12, syntax_cases_expected12);
    }
    SECTION("regex after keyword")
    {
        NORMALIZE(syntax_cases_buf13, syntax_cases_expected13);
        VALIDATE(syntax_cases_buf13, syntax_cases_expected13);
    }
    SECTION("white space between '+'<-->'++' and '-'<-->'--'")
    {
        NORMALIZE(syntax_cases_buf14, syntax_cases_expected14);
        VALIDATE(syntax_cases_buf14, syntax_cases_expected14);
    }
    SECTION("LS and PS chars within literal")
    {
        NORMALIZE(syntax_cases_buf15, syntax_cases_expected15);
        VALIDATE(syntax_cases_buf15, syntax_cases_expected15);
    }
    SECTION("explicit LF within literal")
    {
        NORMALIZE(syntax_cases_buf16, syntax_cases_expected16);
        VALIDATE(syntax_cases_buf16, syntax_cases_expected16);
    }
    SECTION("explicit CR within literal")
    {
        NORMALIZE(syntax_cases_buf17, syntax_cases_expected17);
        VALIDATE(syntax_cases_buf17, syntax_cases_expected17);
    }
    SECTION("escaped LF-CR sequence within literal")
    {
        NORMALIZE(syntax_cases_buf18, syntax_cases_expected18);
        VALIDATE(syntax_cases_buf18, syntax_cases_expected18);
    }
    SECTION("escaped LF within regex literal")
    {
        NORMALIZE(syntax_cases_buf19, syntax_cases_expected19);
        VALIDATE(syntax_cases_buf19, syntax_cases_expected19);
    }
    SECTION("escaped CR-LF within regex literal")
    {
        NORMALIZE(syntax_cases_buf20, syntax_cases_expected20);
        VALIDATE(syntax_cases_buf20, syntax_cases_expected20);
    }
}

TEST_CASE("norm_depth is specified", "[JSNormalizer]")
{
    const char srcbuf[] = "var abc = 123;\n\r";
    const char expected[] = "var abc";
    char dstbuf[7];
    int bytes_copied;
    const char* ptr = srcbuf;
    JSNormState state;
    state.norm_depth = 7;
    state.alerts = 0;
    int ret = JSNormalizer::normalize(srcbuf, sizeof(srcbuf), dstbuf, sizeof(dstbuf), &ptr,
        &bytes_copied, state);

    CHECK(ret == 0);
    CHECK(bytes_copied == sizeof(expected) - 1);
    CHECK(!memcmp(dstbuf, expected, bytes_copied));
}

TEST_CASE("tag script end is specified", "[JSNormalizer]")
{
    const char srcbuf[] =
        "var a = 1 ;\n" // 12 bytes
        "var b = 2 ;\n" // 12 bytes --> ptr_offset = 24
        "</script>\n"
        "var c = 3 ;\n";
    const int ptr_offset = 24;
    const char expected[] = "var a=1;var b=2;";
    char dstbuf[sizeof(expected)];
    int bytes_copied;
    const char* ptr = srcbuf;
    JSNormState state;
    state.norm_depth = NORM_DEPTH;
    state.alerts = 0;
    int ret = JSNormalizer::normalize(srcbuf, sizeof(srcbuf), dstbuf, sizeof(dstbuf), &ptr,
        &bytes_copied, state);

    CHECK(ret == 0);
    CHECK(bytes_copied == sizeof(expected) - 1);
    CHECK((ptr - srcbuf) == ptr_offset);
    CHECK(!memcmp(dstbuf, expected, bytes_copied));
}

// Tests for JavaScript parsing errors and anomalies

TEST_CASE("parsing errors", "[JSNormalizer]")
{
    SECTION("dstlen is too small")
    {
        const char srcbuf[] = "var abc = 123;\n\r";
        const char expected[] = "var abc";
        char dstbuf[7];
        int bytes_copied;
        const char* ptr = srcbuf;
        JSNormState state;
        state.norm_depth = NORM_DEPTH;
        state.alerts = 0;
        int ret = JSNormalizer::normalize(srcbuf, sizeof(srcbuf), dstbuf, sizeof(dstbuf), &ptr,
            &bytes_copied, state);

        CHECK(ret == 1);
        CHECK(bytes_copied == sizeof(expected) - 1);
        CHECK(!memcmp(dstbuf, expected, bytes_copied));
    }
}

static const char unexpected_tag_buf0[] =
    "var a = 1;\n"
    "<script>\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected0[] =
    "var a=1;";

static const char unexpected_tag_buf1[] =
    "var a = 1;\n"
    "<script type=application/javascript>\n"
    "var b = 2;\r\n";;

static const char unexpected_tag_expected1[] =
    "var a=1;";

static const char unexpected_tag_buf2[] =
    "var a = 1;\n"
    "var str = '<script> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected2[] =
    "var a=1;var str=";

static const char unexpected_tag_buf3[] =
    "var a = 1;\n"
    "var str = 'something <script> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected3[] =
    "var a=1;var str=";

static const char unexpected_tag_buf4[] =
    "var a = 1;\n"
    "var str = 'something <script>';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected4[] =
    "var a=1;var str=";

static const char unexpected_tag_buf5[] =
    "var a = 1;\n"
    "var str = '</script> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected5[] =
    "var a=1;var str=";

static const char unexpected_tag_buf6[] =
    "var a = 1;\n"
    "var str = 'something </script> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected6[] =
    "var a=1;var str=";

static const char unexpected_tag_buf7[] =
    "var a = 1;\n"
    "var str = 'something </script>';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected7[] =
    "var a=1;var str=";

static const char unexpected_tag_buf8[] =
    "var a = 1;\n"
    "var str = 'something \\<script\\> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected8[] =
    "var a=1;var str='something \\<script\\> something';var b=2;";

static const char unexpected_tag_buf9[] =
    "var a = 1;\n"
    "var str = 'something \\<\\/script\\> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected9[] =
    "var a=1;var str='something \\<\\/script\\> something';var b=2;";

static const char unexpected_tag_buf10[] =
    "var a = 1;\n"
    "//<script> something\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected10[] =
    "var a=1;";

static const char unexpected_tag_buf11[] =
    "var a = 1;\n"
    "//something <script> something\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected11[] =
    "var a=1;";

static const char unexpected_tag_buf12[] =
    "var a = 1;\n"
    "//something <script>\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected12[] =
    "var a=1;";

static const char unexpected_tag_buf13[] =
    "var a = 1;\n"
    "/*<script> something*/\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected13[] =
    "var a=1;";

static const char unexpected_tag_buf14[] =
    "var a = 1;\n"
    "/*something <script> something*/\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected14[] =
    "var a=1;";

static const char unexpected_tag_buf15[] =
    "var a = 1;\n"
    "/*something <script>*/\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected15[] =
    "var a=1;";

static const char unexpected_tag_buf16[] =
    "var a = 1;\n"
    "//</script> something\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected16[] =
    "var a=1;";

static const char unexpected_tag_buf17[] =
    "var a = 1;\n"
    "<!--something </script> something//-->\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected17[] =
    "var a=1;";

static const char unexpected_tag_buf18[] =
    "var a = 1;\n"
    "//something </script>\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected18[] =
    "var a=1;";

static const char unexpected_tag_buf19[] =
    "var a = 1;\n"
    "/*</script>\n"
    "something*/\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected19[] =
    "var a=1;";

static const char unexpected_tag_buf20[] =
    "var a = 1;\n"
    "/*something\n"
    "</script>\n"
    "something*/\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected20[] =
    "var a=1;";

static const char unexpected_tag_buf21[] =
    "var a = 1;\n"
    "/*something\n"
    "</script>*/\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected21[] =
    "var a=1;";

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
    "var a=1;var str=";

static const char unexpected_tag_buf24[] =
    "var a = 1;\n"
    "var str = 'something <sCrIpT>';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected24[] =
    "var a=1;var str=";

TEST_CASE("unexpected script tag alert", "[JSNormalizer]")
{
    const int ret_code = 1;
    SECTION("explicit open tag - simple")
    {
        NORMALIZE(unexpected_tag_buf0, unexpected_tag_expected0);
        VALIDATE_FAIL(unexpected_tag_buf0, unexpected_tag_expected0, ret_code, 18);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("explicit open tag - complex")
    {
        NORMALIZE(unexpected_tag_buf1, unexpected_tag_expected1);
        VALIDATE_FAIL(unexpected_tag_buf1, unexpected_tag_expected1, ret_code, 18);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("open tag within literal - start")
    {
        NORMALIZE(unexpected_tag_buf2, unexpected_tag_expected2);
        VALIDATE_FAIL(unexpected_tag_buf2, unexpected_tag_expected2, ret_code, 41);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("open tag within literal - mid")
    {
        NORMALIZE(unexpected_tag_buf3, unexpected_tag_expected3);
        VALIDATE_FAIL(unexpected_tag_buf3, unexpected_tag_expected3, ret_code, 51);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("open tag within literal - end")
    {
        NORMALIZE(unexpected_tag_buf4, unexpected_tag_expected4);
        VALIDATE_FAIL(unexpected_tag_buf4, unexpected_tag_expected4, ret_code, 41);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("close tag within literal - start")
    {
        NORMALIZE(unexpected_tag_buf5, unexpected_tag_expected5);
        VALIDATE_FAIL(unexpected_tag_buf5, unexpected_tag_expected5, ret_code, 42);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("close tag within literal - mid")
    {
        NORMALIZE(unexpected_tag_buf6, unexpected_tag_expected6);
        VALIDATE_FAIL(unexpected_tag_buf6, unexpected_tag_expected6, ret_code, 52);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("close tag within literal - end")
    {
        NORMALIZE(unexpected_tag_buf7, unexpected_tag_expected7);
        VALIDATE_FAIL(unexpected_tag_buf7, unexpected_tag_expected7, ret_code, 42);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("open tag within literal - escaped")
    {
        NORMALIZE(unexpected_tag_buf8, unexpected_tag_expected8);
        VALIDATE(unexpected_tag_buf8, unexpected_tag_expected8);
    }
    SECTION("close tag within literal - escaped")
    {
        NORMALIZE(unexpected_tag_buf9, unexpected_tag_expected9);
        VALIDATE(unexpected_tag_buf9, unexpected_tag_expected9);
    }
    SECTION("open tag within single-line comment - start")
    {
        NORMALIZE(unexpected_tag_buf10, unexpected_tag_expected10);
        VALIDATE_FAIL(unexpected_tag_buf10, unexpected_tag_expected10, ret_code, 32);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("open tag within single-line comment - mid")
    {
        NORMALIZE(unexpected_tag_buf11, unexpected_tag_expected11);
        VALIDATE_FAIL(unexpected_tag_buf11, unexpected_tag_expected11, ret_code, 42);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("open tag within single-line comment - end")
    {
        NORMALIZE(unexpected_tag_buf12, unexpected_tag_expected12);
        VALIDATE_FAIL(unexpected_tag_buf12, unexpected_tag_expected12, ret_code, 32);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("open tag within multi-line comment - start")
    {
        NORMALIZE(unexpected_tag_buf13, unexpected_tag_expected13);
        VALIDATE_FAIL(unexpected_tag_buf13, unexpected_tag_expected13, ret_code, 33);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("open tag within multi-line comment - mid")
    {
        NORMALIZE(unexpected_tag_buf14, unexpected_tag_expected14);
        VALIDATE_FAIL(unexpected_tag_buf14, unexpected_tag_expected14, ret_code, 43);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("open tag within multi-line comment - end")
    {
        NORMALIZE(unexpected_tag_buf15, unexpected_tag_expected15);
        VALIDATE_FAIL(unexpected_tag_buf15, unexpected_tag_expected15, ret_code, 33);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("close tag within single-line comment - start")
    {
        NORMALIZE(unexpected_tag_buf16, unexpected_tag_expected16);
        VALIDATE_FAIL(unexpected_tag_buf16, unexpected_tag_expected16, ret_code, 33);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("close tag within single-line comment - mid")
    {
        NORMALIZE(unexpected_tag_buf17, unexpected_tag_expected17);
        VALIDATE_FAIL(unexpected_tag_buf17, unexpected_tag_expected17, ret_code, 50);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("close tag within single-line comment - end")
    {
        NORMALIZE(unexpected_tag_buf18, unexpected_tag_expected18);
        VALIDATE_FAIL(unexpected_tag_buf18, unexpected_tag_expected18, ret_code, 33);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("close tag within multi-line comment - start")
    {
        NORMALIZE(unexpected_tag_buf19, unexpected_tag_expected19);
        VALIDATE_FAIL(unexpected_tag_buf19, unexpected_tag_expected19, ret_code, 34);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("close tag within multi-line comment - mid")
    {
        NORMALIZE(unexpected_tag_buf20, unexpected_tag_expected20);
        VALIDATE_FAIL(unexpected_tag_buf20, unexpected_tag_expected20, ret_code, 44);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("close tag within multi-line comment - end")
    {
        NORMALIZE(unexpected_tag_buf21, unexpected_tag_expected21);
        VALIDATE_FAIL(unexpected_tag_buf21, unexpected_tag_expected21, ret_code, 34);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("multiple patterns - not matched")
    {
        NORMALIZE(unexpected_tag_buf22, unexpected_tag_expected22);
        VALIDATE(unexpected_tag_buf22, unexpected_tag_expected22);
    }
    SECTION("multiple patterns - matched")
    {
        NORMALIZE(unexpected_tag_buf23, unexpected_tag_expected23);
        VALIDATE_FAIL(unexpected_tag_buf23, unexpected_tag_expected23, ret_code, 67);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
    SECTION("mixed lower and upper case")
    {
        NORMALIZE(unexpected_tag_buf24, unexpected_tag_expected24);
        VALIDATE_FAIL(unexpected_tag_buf24, unexpected_tag_expected24, ret_code, 41);
        VALIDATE_ALERT(ALERT_UNEXPECTED_TAG);
    }
}

