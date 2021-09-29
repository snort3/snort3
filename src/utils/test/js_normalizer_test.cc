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

#include "utils/js_identifier_ctx.h"
#include "utils/js_normalizer.h"

// Mock functions

namespace snort
{
[[noreturn]] void FatalError(const char*, ...)
{ exit(EXIT_FAILURE); }
void trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) {}
uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(const Packet&) {}
}

THREAD_LOCAL const snort::Trace* http_trace = nullptr;

class JSIdentifierCtxTest : public JSIdentifierCtxBase
{
public:
    JSIdentifierCtxTest() = default;

    const char* substitute(const char* identifier) override
    { return identifier; }
    void reset() override {}
    size_t size() const override { return 0; }
};

// Test cases

using namespace snort;

#define DEPTH 65535
#define MAX_TEMPLATE_NESTNIG 4

// Unit tests

#ifdef CATCH_TEST_BUILD

#define DST_SIZE 512

#define NORMALIZE(src)                                             \
    JSIdentifierCtxTest ident_ctx;                                 \
    JSNormalizer norm(ident_ctx, DEPTH, MAX_TEMPLATE_NESTNIG);     \
    auto ret = norm.normalize(src, sizeof(src));                   \
    const char* ptr = norm.get_src_next();                         \
    auto result = norm.get_script();                               \
    char* dst = result.first;                                      \
    int act_len = result.second;                                   \

#define VALIDATE(src, expected)                 \
    CHECK(ret == JSTokenizer::SCRIPT_CONTINUE); \
    CHECK((ptr - src) == sizeof(src));          \
    CHECK(act_len == sizeof(expected) - 1);     \
    CHECK(!memcmp(dst, expected, act_len));     \
    delete[] dst;

#define VALIDATE_FAIL(src, expected, ret_code, ptr_offset) \
    CHECK(ret == ret_code);                                \
    CHECK((ptr - src) == ptr_offset);                      \
    CHECK(act_len == sizeof(expected) - 1);                \
    CHECK(!memcmp(dst, expected, act_len));                \
    delete[] dst;


#define NORMALIZE_L(src, src_len, dst, dst_len, depth, ret, ptr, len) \
    {                                                                 \
        JSIdentifierCtxTest ident_ctx;                                \
        JSNormalizer norm(ident_ctx, depth, MAX_TEMPLATE_NESTNIG);    \
        ret = norm.normalize(src, src_len);                           \
        ptr = norm.get_src_next();                                    \
        auto result = norm.get_script();                              \
        char* dptr = result.first;                                    \
        len = result.second;                                          \
        REQUIRE(len == dst_len);                                      \
        memcpy(dst, dptr, dst_len);                                   \
        delete[] dptr;                                                \
    }

#define DO(src, slen, dst, dlen)                            \
    {                                                       \
        auto ret = norm.normalize(src, slen);               \
        CHECK(ret == JSTokenizer::SCRIPT_CONTINUE);         \
        auto nsrc = norm.get_src_next();                    \
        auto result = norm.get_script();                    \
        char* ptr = result.first;                           \
        int act_len = result.second;                        \
        REQUIRE(nsrc - src == slen);                        \
        REQUIRE(act_len == dlen);                           \
        memcpy(dst, ptr, dlen);                             \
        delete[] ptr;                                       \
    }

#define TRY(src, slen, dst, dlen, rexp)                     \
    {                                                       \
        auto ret = norm.normalize(src, slen);               \
        CHECK(ret == rexp);                                 \
        auto result = norm.get_script();                    \
        char* ptr = result.first;                           \
        int act_len = result.second;                        \
        REQUIRE(act_len == dlen);                           \
        memcpy(dst, ptr, dlen);                             \
        delete[] ptr;                                       \
    }

#define CLOSE()                                                         \
    {                                                                   \
        const char end[] = "</script>";                                 \
        auto ret = norm.normalize(end, sizeof(end) - 1);                \
        CHECK(ret == JSTokenizer::SCRIPT_ENDED);                        \
    }

#define NORMALIZE_2(src1, src2, exp1, exp2)                         \
    {                                                               \
        char dst1[sizeof(exp1)];                                    \
        char dst2[sizeof(exp2)];                                    \
                                                                    \
        JSIdentifierCtxTest ident_ctx;                              \
        JSNormalizer norm(ident_ctx, DEPTH, MAX_TEMPLATE_NESTNIG);  \
                                                                    \
        DO(src1, sizeof(src1) - 1, dst1, sizeof(dst1) - 1);         \
        CHECK(!memcmp(exp1, dst1, sizeof(exp1) - 1));               \
                                                                    \
        DO(src2, sizeof(src2) - 1, dst2, sizeof(dst2) - 1);         \
        CHECK(!memcmp(exp2, dst2, sizeof(exp2) - 1));               \
                                                                    \
        CLOSE();                                                    \
    }

#define NORMALIZE_3(src1, src2, src3, exp1, exp2, exp3)             \
    {                                                               \
        char dst1[sizeof(exp1)];                                    \
        char dst2[sizeof(exp2)];                                    \
        char dst3[sizeof(exp3)];                                    \
                                                                    \
        JSIdentifierCtxTest ident_ctx;                              \
        JSNormalizer norm(ident_ctx, DEPTH, MAX_TEMPLATE_NESTNIG);  \
                                                                    \
        DO(src1, sizeof(src1) - 1, dst1, sizeof(dst1) - 1);         \
        CHECK(!memcmp(exp1, dst1, sizeof(exp1) - 1));               \
                                                                    \
        DO(src2, sizeof(src2) - 1, dst2, sizeof(dst2) - 1);         \
        CHECK(!memcmp(exp2, dst2, sizeof(exp2) - 1));               \
                                                                    \
        DO(src3, sizeof(src3) - 1, dst3, sizeof(dst3) - 1);         \
        CHECK(!memcmp(exp3, dst3, sizeof(exp3) - 1));               \
                                                                    \
        CLOSE();                                                    \
    }

#define NORM_BAD_2(src1, src2, exp1, exp2, code)                    \
    {                                                               \
        char dst1[sizeof(exp1)];                                    \
        char dst2[sizeof(exp2)];                                    \
                                                                    \
        JSIdentifierCtxTest ident_ctx;                              \
        JSNormalizer norm(ident_ctx, DEPTH, MAX_TEMPLATE_NESTNIG);  \
                                                                    \
        DO(src1, sizeof(src1) - 1, dst1, sizeof(dst1) - 1);         \
        CHECK(!memcmp(exp1, dst1, sizeof(exp1) - 1));               \
                                                                    \
        TRY(src2, sizeof(src2) - 1, dst2, sizeof(dst2) - 1, code);  \
        CHECK(!memcmp(exp2, dst2, sizeof(exp2) - 1));               \
    }

#define NORM_BAD_3(src1, src2, src3, exp1, exp2, exp3, code)        \
    {                                                               \
        char dst1[sizeof(exp1)];                                    \
        char dst2[sizeof(exp2)];                                    \
        char dst3[sizeof(exp3)];                                    \
                                                                    \
        JSIdentifierCtxTest ident_ctx;                              \
        JSNormalizer norm(ident_ctx, DEPTH, MAX_TEMPLATE_NESTNIG);  \
                                                                    \
        DO(src1, sizeof(src1) - 1, dst1, sizeof(dst1) - 1);         \
        CHECK(!memcmp(exp1, dst1, sizeof(exp1) - 1));               \
                                                                    \
        DO(src2, sizeof(src2) - 1, dst2, sizeof(dst2) - 1);         \
        CHECK(!memcmp(exp2, dst2, sizeof(exp2) - 1));               \
                                                                    \
        TRY(src3, sizeof(src3) - 1, dst3, sizeof(dst3) - 1, code);  \
        CHECK(!memcmp(exp3, dst3, sizeof(exp3) - 1));               \
    }

#define NORM_LIMITED(limit, src1, src2, exp1, exp2)                     \
    {                                                                   \
        char dst1[sizeof(exp1)];                                        \
        char dst2[sizeof(exp2)];                                        \
                                                                        \
        JSIdentifierCtxTest ident_ctx;                                  \
        JSNormalizer norm(ident_ctx, DEPTH, MAX_TEMPLATE_NESTNIG, limit); \
                                                                        \
        DO(src1, sizeof(src1) - 1, dst1, sizeof(dst1) - 1);             \
        CHECK(!memcmp(exp1, dst1, sizeof(exp1) - 1));                   \
                                                                        \
        DO(src2, sizeof(src2) - 1, dst2, sizeof(dst2) - 1);             \
        CHECK(!memcmp(exp2, dst2, sizeof(exp2) - 1));                   \
                                                                        \
        CLOSE();                                                        \
    }

// ClamAV test vectors from: https://github.com/Cisco-Talos/clamav/blob/main/unit_tests/check_jsnorm.c
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
    SECTION("test_case_0 - mixed identifiers and comments")
    {
        NORMALIZE(clamav_buf0);
        VALIDATE(clamav_buf0, clamav_expected0);
    }
    SECTION("test_case_1 - escaped unicode in identifier")
    {
        NORMALIZE(clamav_buf1);
        VALIDATE(clamav_buf1, clamav_expected1);
    }
    SECTION("test_case_2 - accumulated string assignment")
    {
        NORMALIZE(clamav_buf2);
        VALIDATE(clamav_buf2, clamav_expected2);
    }
    SECTION("test_case_3 - percent-encoded string")
    {
        NORMALIZE(clamav_buf3);
        VALIDATE(clamav_buf3, clamav_expected3);
    }
    SECTION("test_case_4 - percent-encoded string")
    {
        NORMALIZE(clamav_buf4);
        VALIDATE(clamav_buf4, clamav_expected4);
    }
    SECTION("test_case_5 - obfuscated script")
    {
        NORMALIZE(clamav_buf5);
        VALIDATE(clamav_buf5, clamav_expected5);
    }
    SECTION("test_case_6 - obfuscated script")
    {
        NORMALIZE(clamav_buf6);
        VALIDATE(clamav_buf6, clamav_expected6);
    }
    SECTION("test_case_7 - single quotes string")
    {
        NORMALIZE(clamav_buf7);
        VALIDATE(clamav_buf7, clamav_expected7);
    }
    SECTION("test_case_8 - double quotes string")
    {
        NORMALIZE(clamav_buf8);
        VALIDATE(clamav_buf8, clamav_expected8);
    }
    SECTION("test_case_9 - obfuscated script")
    {
        NORMALIZE(clamav_buf9);
        VALIDATE(clamav_buf9, clamav_expected9);
    }
    SECTION("test_case_10 - obfuscated script")
    {
        NORMALIZE(clamav_buf10);
        VALIDATE(clamav_buf10, clamav_expected10);
    }
    SECTION("test_case_11 - integer literal")
    {
        NORMALIZE(clamav_buf11);
        VALIDATE(clamav_buf11, clamav_expected11);
    }
    SECTION("test_case_12 - escaped unicode in string literal")
    {
        NORMALIZE(clamav_buf12);
        VALIDATE(clamav_buf12, clamav_expected12);
    }
    // FIXIT-L this should be revisited
    SECTION("test_case_13 - invalid escape sequence")
    {
        NORMALIZE(clamav_buf13);
        VALIDATE(clamav_buf13, clamav_expected13);
    }
    SECTION("test_case_14 - EOF in the middle of string literal")
    {
        NORMALIZE(clamav_buf14);
        // trailing \0 is included as a part of the string
        // to utilize available macros we alter the read length
        act_len -= 1;
        VALIDATE(clamav_buf14, clamav_expected14);
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
    "x=2/2/1 `\ntemplate\n`";

static const char all_patterns_expected4[] =
    "/regex/g undefined null true false 2 23 2.3 2.23 .2 .02 4.+2-2"
    "+3.3-3.3+23-32 2.3E45 3.E34-2.3E45-3.E34+2.3E45+3.E34 0x1234 0XFFFF Infinity "
    "\xE2\x88\x9E NaN \"\" \"double string\" \"d\" '' 'single string' 's' x=/regex/gs "
    "x=2/2/1 `\ntemplate\n`";

static const char all_patterns_buf5[] =
    "$2abc _2abc abc $__$ 肖晗 XÆA12 \\u0041abc \\u00FBdef \\u1234ghi ab\xE2\x80\xA8ww "
    "ab\xE2\x80\xA9ww ab\xEF\xBB\xBFww ab∞ww 2abc";

static const char all_patterns_expected5[] =
    "$2abc _2abc abc $__$ 肖晗 XÆA12 \u0041abc \u00FBdef \u1234ghi ab ww "
    "ab ww ab ww ab ∞ ww 2 abc";

static const char all_patterns_buf6[] =
    "tag` template\n   ${ a   +   b }   template`";

static const char all_patterns_expected6[] =
    "tag ` template\n   ${a+b}   template`";

TEST_CASE("all patterns", "[JSNormalizer]")
{
    SECTION("whitespaces and special characters")
    {
        NORMALIZE(all_patterns_buf0);
        VALIDATE(all_patterns_buf0, all_patterns_expected0);
    }
    SECTION("comments")
    {
        NORMALIZE(all_patterns_buf1);
        VALIDATE(all_patterns_buf1, all_patterns_expected1);
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

        char dst0[sizeof(expected0) - 1];
        char dst1[sizeof(expected1) - 1];
        char dst2[sizeof(expected0) - 1];
        char dst3[sizeof(expected1) - 1];
        char dst4[sizeof(expected2) - 1];

        int ret0, ret1, ret2, ret3, ret4;
        const char *ptr0, *ptr1, *ptr2, *ptr3, *ptr4;
        int act_len0, act_len1, act_len2, act_len3, act_len4;

        NORMALIZE_L(src0, sizeof(src0), dst0, sizeof(dst0), DEPTH, ret0, ptr0, act_len0);
        NORMALIZE_L(src1, sizeof(src1), dst1, sizeof(dst1), DEPTH, ret1, ptr1, act_len1);
        NORMALIZE_L(src2, sizeof(src2), dst2, sizeof(dst2), DEPTH, ret2, ptr2, act_len2);
        NORMALIZE_L(src3, sizeof(src3), dst3, sizeof(dst3), DEPTH, ret3, ptr3, act_len3);
        NORMALIZE_L(src4, sizeof(src4), dst4, sizeof(dst4), DEPTH, ret4, ptr4, act_len4);

        CHECK(ret0 == JSTokenizer::SCRIPT_CONTINUE);
        CHECK((ptr0 - src0) == sizeof(src0));
        CHECK(act_len0 == sizeof(expected0) - 1);
        CHECK(!memcmp(dst0, expected0, act_len0));

        CHECK(ret1 == JSTokenizer::SCRIPT_CONTINUE);
        CHECK((ptr1 - src1) == sizeof(src1));
        CHECK(act_len1 == sizeof(expected1) - 1);
        CHECK(!memcmp(dst1, expected1, act_len1));

        CHECK(ret2 == JSTokenizer::SCRIPT_CONTINUE);
        CHECK((ptr2 - src2) == sizeof(src2));
        CHECK(act_len2 == sizeof(expected0) - 1);
        CHECK(!memcmp(dst2, expected0, act_len2));

        CHECK(ret3 == JSTokenizer::SCRIPT_CONTINUE);
        CHECK((ptr3 - src3) == sizeof(src3));
        CHECK(act_len3 == sizeof(expected1) - 1);
        CHECK(!memcmp(dst3, expected1, act_len3));

        CHECK(ret4 == JSTokenizer::SCRIPT_CONTINUE);
        CHECK((ptr4 - src4) == sizeof(src4));
        CHECK(act_len4 == sizeof(expected2) - 1);
        CHECK(!memcmp(dst4, expected2, act_len4));
    }
    SECTION("punctuators")
    {
        NORMALIZE(all_patterns_buf2);
        VALIDATE(all_patterns_buf2, all_patterns_expected2);
    }
    SECTION("keywords")
    {
        NORMALIZE(all_patterns_buf3);
        VALIDATE(all_patterns_buf3, all_patterns_expected3);
    }
    SECTION("literals")
    {
        NORMALIZE(all_patterns_buf4);
        VALIDATE(all_patterns_buf4, all_patterns_expected4);
    }
    SECTION("identifiers")
    {
        NORMALIZE(all_patterns_buf5);
        VALIDATE(all_patterns_buf5, all_patterns_expected5);
    }
    SECTION("template literals")
    {
        NORMALIZE(all_patterns_buf6);
        VALIDATE(all_patterns_buf6, all_patterns_expected6);
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

// In the following cases:
//   a reading cursor will be after the literal
//   a malformed literal is not present in the output

static const char syntax_cases_buf15[] =
    "var invalid_str = 'abc\u2028 def' ;\n";

static const char syntax_cases_expected15[] =
    "var invalid_str='abc";

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
    "var invalid_str='abc";

static const char syntax_cases_buf22[] =
    "tag`template\n \\\\\\${   }   \\\\${   a  + ` template ${ 1 + c  }`  }`";

static const char syntax_cases_expected22[] =
    "tag `template\n \\\\\\${   }   \\\\${a+` template ${1+c}`}`";

static const char syntax_cases_buf23[] =
    "`${`${`${`${`${}`}`}`}`}`}";

static const char syntax_cases_expected23[] =
    "`${`${`${`${`";

TEST_CASE("syntax cases", "[JSNormalizer]")
{
    SECTION("variables")
    {
        NORMALIZE(syntax_cases_buf0);
        VALIDATE(syntax_cases_buf0, syntax_cases_expected0);
    }
    SECTION("operators")
    {
        NORMALIZE(syntax_cases_buf1);
        VALIDATE(syntax_cases_buf1, syntax_cases_expected1);
    }
    SECTION("arithmetic and logical operators")
    {
        NORMALIZE(syntax_cases_buf2);
        VALIDATE(syntax_cases_buf2, syntax_cases_expected2);
    }
    SECTION("complex object")
    {
        NORMALIZE(syntax_cases_buf3);
        VALIDATE(syntax_cases_buf3, syntax_cases_expected3);
    }
    SECTION("arrays")
    {
        NORMALIZE(syntax_cases_buf4);
        VALIDATE(syntax_cases_buf4, syntax_cases_expected4);
    }
    SECTION("loops")
    {
        NORMALIZE(syntax_cases_buf5);
        VALIDATE(syntax_cases_buf5, syntax_cases_expected5);
    }
    SECTION("if-else and switch statements")
    {
        NORMALIZE(syntax_cases_buf6);
        VALIDATE(syntax_cases_buf6, syntax_cases_expected6);
    }
    SECTION("try-catch statements")
    {
        NORMALIZE(syntax_cases_buf7);
        VALIDATE(syntax_cases_buf7, syntax_cases_expected7);
    }
    SECTION("functions and promises")
    {
        NORMALIZE(syntax_cases_buf8);
        VALIDATE(syntax_cases_buf8, syntax_cases_expected8);
    }
    SECTION("regex-division ambiguity")
    {
        NORMALIZE(syntax_cases_buf9);
        VALIDATE(syntax_cases_buf9, syntax_cases_expected9);
    }
    SECTION("regex on a new line")
    {
        NORMALIZE(syntax_cases_buf10);
        VALIDATE(syntax_cases_buf10, syntax_cases_expected10);
    }
    SECTION("string and regex literals ambiguity with escaped sentinel chars")
    {
        NORMALIZE(syntax_cases_buf11);
        VALIDATE(syntax_cases_buf11, syntax_cases_expected11);
    }
    SECTION("escaped LF and CR chars in literals")
    {
        NORMALIZE(syntax_cases_buf12);
        VALIDATE(syntax_cases_buf12, syntax_cases_expected12);
    }
    SECTION("regex after keyword")
    {
        NORMALIZE(syntax_cases_buf13);
        VALIDATE(syntax_cases_buf13, syntax_cases_expected13);
    }
    SECTION("white space between '+'<-->'++' and '-'<-->'--'")
    {
        NORMALIZE(syntax_cases_buf14);
        VALIDATE(syntax_cases_buf14, syntax_cases_expected14);
    }
    SECTION("template literals")
    {
        NORMALIZE(syntax_cases_buf22);
        VALIDATE(syntax_cases_buf22, syntax_cases_expected22);
    }
}

TEST_CASE("bad tokens", "[JSNormalizer]")
{
    SECTION("LS chars within literal")
    {
        NORMALIZE(syntax_cases_buf15);
        VALIDATE_FAIL(syntax_cases_buf15, syntax_cases_expected15, JSTokenizer::BAD_TOKEN, 25);
    }
    SECTION("PS chars within literal")
    {
        NORMALIZE(syntax_cases_buf21);
        VALIDATE_FAIL(syntax_cases_buf21, syntax_cases_expected21, JSTokenizer::BAD_TOKEN, 25);
    }
    SECTION("explicit LF within literal")
    {
        NORMALIZE(syntax_cases_buf16);
        VALIDATE_FAIL(syntax_cases_buf16, syntax_cases_expected16, JSTokenizer::BAD_TOKEN, 23);
    }
    SECTION("explicit CR within literal")
    {
        NORMALIZE(syntax_cases_buf17);
        VALIDATE_FAIL(syntax_cases_buf17, syntax_cases_expected17, JSTokenizer::BAD_TOKEN, 23);
    }
    SECTION("escaped LF-CR sequence within literal")
    {
        NORMALIZE(syntax_cases_buf18);
        VALIDATE_FAIL(syntax_cases_buf18, syntax_cases_expected18, JSTokenizer::BAD_TOKEN, 25);
    }
    SECTION("escaped LF within regex literal")
    {
        NORMALIZE(syntax_cases_buf19);
        VALIDATE_FAIL(syntax_cases_buf19, syntax_cases_expected19, JSTokenizer::BAD_TOKEN, 23);
    }
    SECTION("escaped CR-LF within regex literal")
    {
        NORMALIZE(syntax_cases_buf20);
        VALIDATE_FAIL(syntax_cases_buf20, syntax_cases_expected20, JSTokenizer::BAD_TOKEN, 23);
    }
}

TEST_CASE("template literal overflow", "[JSNormalizer]")
{
    SECTION("exceeding template literal limit")
    {
        NORMALIZE(syntax_cases_buf23);
        VALIDATE_FAIL(syntax_cases_buf23, syntax_cases_expected23,
            JSTokenizer::TEMPLATE_NESTING_OVERFLOW, 15);
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
        char dst[sizeof(expected) - 1];
        int act_len;
        const char* ptr;
        int ret;

        NORMALIZE_L(src, sizeof(src), dst, sizeof(dst), DEPTH, ret, ptr, act_len);

        CHECK(ret == JSTokenizer::SCRIPT_ENDED);
        CHECK(act_len == sizeof(expected) - 1);
        CHECK((ptr - src) == ptr_offset);
        CHECK(!memcmp(dst, expected, act_len));
    }
    SECTION("depth reached", "[JSNormalizer]")
    {
        const char src[] = "var abc = 123;\n\r";
        const char src2[] = "var foo = 321;\n\r";
        const char expected[] = "var abc";
        const char* ptr;
        int ret;

        JSIdentifierCtxTest ident_ctx;
        JSNormalizer norm(ident_ctx, 7, MAX_TEMPLATE_NESTNIG);
        ret = norm.normalize(src, sizeof(src));
        ptr = norm.get_src_next();
        auto res1 = norm.get_script();
        char* dst1 = res1.first;
        int act_len1 = res1.second;

        CHECK(ret == JSTokenizer::EOS);
        CHECK(ptr == src + 7);
        CHECK(act_len1 == sizeof(expected) - 1);
        CHECK(!memcmp(dst1, expected, act_len1));
        delete[] dst1;

        ret = norm.normalize(src2, sizeof(src2));
        ptr = norm.get_src_next();
        auto res2 = norm.get_script();
        char* dst2 = res2.first;
        int act_len2 = res2.second;

        CHECK(ret == JSTokenizer::EOS);
        CHECK(ptr == src2 + sizeof(src2));
        CHECK(act_len2 == 0);
        delete[] dst2;
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
    "var b = 2;\r\n";

static const char unexpected_tag_expected1[] =
    "var a=1;";

static const char unexpected_tag_buf2[] =
    "var a = 1;\n"
    "var str = '<script> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected2[] =
    "var a=1;var str='";

static const char unexpected_tag_buf3[] =
    "var a = 1;\n"
    "var str = 'something <script> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected3[] =
    "var a=1;var str='something ";

static const char unexpected_tag_buf4[] =
    "var a = 1;\n"
    "var str = 'something <script>';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected4[] =
    "var a=1;var str='something ";

static const char unexpected_tag_buf5[] =
    "var a = 1;\n"
    "var str = '</script> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected5[] =
    "var a=1;var str='";

static const char unexpected_tag_buf6[] =
    "var a = 1;\n"
    "var str = 'something </script> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected6[] =
    "var a=1;var str='something ";

static const char unexpected_tag_buf7[] =
    "var a = 1;\n"
    "var str = 'something </script>';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected7[] =
    "var a=1;var str='something ";

static const char unexpected_tag_buf8[] =
    "var a = 1;\n"
    "var str = 'something \\<script\\> something';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected8[] =
    "var a=1;var str='something \\";

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
    "var a=1;var str='script somescript /script something ";

static const char unexpected_tag_buf24[] =
    "var a = 1;\n"
    "var str = 'something <sCrIpT>';\n"
    "var b = 2;\r\n";

static const char unexpected_tag_expected24[] =
    "var a=1;var str='something ";

TEST_CASE("nested script tags", "[JSNormalizer]")
{
    SECTION("explicit open tag - simple")
    {
        NORMALIZE(unexpected_tag_buf0);
        VALIDATE_FAIL(unexpected_tag_buf0, unexpected_tag_expected0, JSTokenizer::OPENING_TAG, 18);
    }
    SECTION("explicit open tag - complex")
    {
        NORMALIZE(unexpected_tag_buf1);
        VALIDATE_FAIL(unexpected_tag_buf1, unexpected_tag_expected1, JSTokenizer::OPENING_TAG, 18);
    }
    SECTION("open tag within literal - start")
    {
        NORMALIZE(unexpected_tag_buf2);
        VALIDATE_FAIL(unexpected_tag_buf2, unexpected_tag_expected2, JSTokenizer::OPENING_TAG, 29);
    }
    SECTION("open tag within literal - mid")
    {
        NORMALIZE(unexpected_tag_buf3);
        VALIDATE_FAIL(unexpected_tag_buf3, unexpected_tag_expected3, JSTokenizer::OPENING_TAG, 39);
    }
    SECTION("open tag within literal - end")
    {
        NORMALIZE(unexpected_tag_buf4);
        VALIDATE_FAIL(unexpected_tag_buf4, unexpected_tag_expected4, JSTokenizer::OPENING_TAG, 39);
    }
    SECTION("close tag within literal - start")
    {
        NORMALIZE(unexpected_tag_buf5);
        VALIDATE_FAIL(unexpected_tag_buf5, unexpected_tag_expected5, JSTokenizer::CLOSING_TAG, 31);
    }
    SECTION("close tag within literal - mid")
    {
        NORMALIZE(unexpected_tag_buf6);
        VALIDATE_FAIL(unexpected_tag_buf6, unexpected_tag_expected6, JSTokenizer::CLOSING_TAG, 41);
    }
    SECTION("close tag within literal - end")
    {
        NORMALIZE(unexpected_tag_buf7);
        VALIDATE_FAIL(unexpected_tag_buf7, unexpected_tag_expected7, JSTokenizer::CLOSING_TAG, 41);
    }
    SECTION("open tag within literal - escaped")
    {
        NORMALIZE(unexpected_tag_buf8);
        VALIDATE_FAIL(unexpected_tag_buf8, unexpected_tag_expected8, JSTokenizer::OPENING_TAG, 40);
    }
    SECTION("close tag within literal - escaped")
    {
        NORMALIZE(unexpected_tag_buf9);
        VALIDATE(unexpected_tag_buf9, unexpected_tag_expected9);
    }
    SECTION("open tag within single-line comment - start")
    {
        NORMALIZE(unexpected_tag_buf10);
        VALIDATE_FAIL(unexpected_tag_buf10, unexpected_tag_expected10, JSTokenizer::OPENING_TAG, 20);
    }
    SECTION("open tag within single-line comment - mid")
    {
        NORMALIZE(unexpected_tag_buf11);
        VALIDATE_FAIL(unexpected_tag_buf11, unexpected_tag_expected11, JSTokenizer::OPENING_TAG, 30);
    }
    SECTION("open tag within single-line comment - end")
    {
        NORMALIZE(unexpected_tag_buf12);
        VALIDATE_FAIL(unexpected_tag_buf12, unexpected_tag_expected12, JSTokenizer::OPENING_TAG, 30);
    }
    SECTION("open tag within multi-line comment - start")
    {
        NORMALIZE(unexpected_tag_buf13);
        VALIDATE_FAIL(unexpected_tag_buf13, unexpected_tag_expected13, JSTokenizer::OPENING_TAG, 20);
    }
    SECTION("open tag within multi-line comment - mid")
    {
        NORMALIZE(unexpected_tag_buf14);
        VALIDATE_FAIL(unexpected_tag_buf14, unexpected_tag_expected14, JSTokenizer::OPENING_TAG, 30);
    }
    SECTION("open tag within multi-line comment - end")
    {
        NORMALIZE(unexpected_tag_buf15);
        VALIDATE_FAIL(unexpected_tag_buf15, unexpected_tag_expected15, JSTokenizer::OPENING_TAG, 30);
    }
    SECTION("close tag within single-line comment - start")
    {
        NORMALIZE(unexpected_tag_buf16);
        VALIDATE_FAIL(unexpected_tag_buf16, unexpected_tag_expected16, JSTokenizer::CLOSING_TAG, 22);
    }
    SECTION("close tag within single-line comment - mid")
    {
        NORMALIZE(unexpected_tag_buf17);
        VALIDATE_FAIL(unexpected_tag_buf17, unexpected_tag_expected17, JSTokenizer::CLOSING_TAG, 34);
    }
    SECTION("close tag within single-line comment - end")
    {
        NORMALIZE(unexpected_tag_buf18);
        VALIDATE_FAIL(unexpected_tag_buf18, unexpected_tag_expected18, JSTokenizer::CLOSING_TAG, 32);
    }
    SECTION("close tag within multi-line comment - start")
    {
        NORMALIZE(unexpected_tag_buf19);
        VALIDATE_FAIL(unexpected_tag_buf19, unexpected_tag_expected19, JSTokenizer::CLOSING_TAG, 22);
    }
    SECTION("close tag within multi-line comment - mid")
    {
        NORMALIZE(unexpected_tag_buf20);
        VALIDATE_FAIL(unexpected_tag_buf20, unexpected_tag_expected20, JSTokenizer::CLOSING_TAG, 32);
    }
    SECTION("close tag within multi-line comment - end")
    {
        NORMALIZE(unexpected_tag_buf21);
        VALIDATE_FAIL(unexpected_tag_buf21, unexpected_tag_expected21, JSTokenizer::CLOSING_TAG, 32);
    }
    SECTION("multiple patterns - not matched")
    {
        NORMALIZE(unexpected_tag_buf22);
        VALIDATE(unexpected_tag_buf22, unexpected_tag_expected22);
    }
    SECTION("multiple patterns - matched")
    {
        NORMALIZE(unexpected_tag_buf23);
        VALIDATE_FAIL(unexpected_tag_buf23, unexpected_tag_expected23, JSTokenizer::OPENING_TAG, 65);
    }
    SECTION("mixed lower and upper case")
    {
        NORMALIZE(unexpected_tag_buf24);
        VALIDATE_FAIL(unexpected_tag_buf24, unexpected_tag_expected24, JSTokenizer::OPENING_TAG, 39);
    }
}

TEST_CASE("split between tokens", "[JSNormalizer]")
{
    SECTION("operator string")
    {
        const char dat1[] = "var s = ";
        const char dat2[] = "'string';";
        const char exp1[] = "var s=";
        const char exp2[] = "var s='string';";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("operator number")
    {
        const char dat1[] = "a = 5 +";
        const char dat2[] = "b + c;";
        const char exp1[] = "a=5+";
        const char exp2[] = "a=5+b+c;";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("comment function")
    {
        const char dat1[] = "// no comments\n";
        const char dat2[] = "foo(bar, baz);";
        const char exp1[] = "";
        const char exp2[] = "foo(bar,baz);";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("operator identifier")
    {
        const char dat1[] = "var ";
        const char dat2[] = "a = ";
        const char dat3[] = "b  ;";
        const char exp1[] = "var";
        const char exp2[] = "var a=";
        const char exp3[] = "var a=b;";

        NORMALIZE_3(dat1, dat2, dat3, exp1, exp2, exp3);
    }
}

TEST_CASE("split in comments", "[JSNormalizer]")
{
    SECTION("/ /")
    {
        const char dat1[] = "/";
        const char dat2[] = "/comment\n";
        const char exp1[] = "/";
        const char exp2[] = "";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("/ / msg")
    {
        const char dat1[] = "//";
        const char dat2[] = "comment\n";
        const char exp1[] = "";
        const char exp2[] = "";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("/ / LF")
    {
        const char dat1[] = "//comment";
        const char dat2[] = "\n";
        const char exp1[] = "";
        const char exp2[] = "";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }

    SECTION("/ *")
    {
        const char dat1[] = "/";
        const char dat2[] = "* comment */";
        const char exp1[] = "/";
        const char exp2[] = "";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("/ * msg")
    {
        const char dat1[] = "/* t";
        const char dat2[] = "ext */";
        const char exp1[] = "";
        const char exp2[] = "";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("* /")
    {
        const char dat1[] = "/* comment *";
        const char dat2[] = "/";
        const char exp1[] = "";
        const char exp2[] = "";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("/ * msg * /")
    {
        const char dat1[] = "/";
        const char dat2[] = "* comment *";
        const char dat3[] = "/";
        const char exp1[] = "/";
        const char exp2[] = "";
        const char exp3[] = "";

        NORMALIZE_3(dat1, dat2, dat3, exp1, exp2, exp3);
    }

    SECTION("< !--")
    {
        const char dat1[] = "<";
        const char dat2[] = "!-- comment\n";
        const char exp1[] = "<";
        const char exp2[] = "";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("<! --")
    {
        const char dat1[] = "<!";
        const char dat2[] = "-- comment\n";
        const char exp1[] = "<!";
        const char exp2[] = "";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("<!- -")
    {
        const char dat1[] = "<!-";
        const char dat2[] = "- comment\n";
        const char exp1[] = "<!-";
        const char exp2[] = "";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("<!-- msg")
    {
        const char dat1[] = "<!--";
        const char dat2[] = "comment\n";
        const char exp1[] = "";
        const char exp2[] = "";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("<! -- msg")
    {
        const char dat1[] = "<";
        const char dat2[] = "!-";
        const char dat3[] = "-comment\n";
        const char exp1[] = "<";
        const char exp2[] = "<!-";
        const char exp3[] = "";

        NORMALIZE_3(dat1, dat2, dat3, exp1, exp2, exp3);
    }
}

TEST_CASE("split in opening tag", "[JSNormalizer]")
{
    SECTION("< script")
    {
        const char dat1[] = "<";
        const char dat2[] = "script";
        const char exp1[] = "<";
        const char exp2[] = "";

        NORM_BAD_2(dat1, dat2, exp1, exp2, JSTokenizer::OPENING_TAG);
    }
    SECTION("str='<s cript'")
    {
        const char dat1[] = "var str ='<s";
        const char dat2[] = "cript';";
        const char exp1[] = "var str='<s";
        const char exp2[] = "var str='";

        NORM_BAD_2(dat1, dat2, exp1, exp2, JSTokenizer::OPENING_TAG);
    }
    SECTION("str='<scrip t'")
    {
        const char dat1[] = "var str ='<scrip";
        const char dat2[] = "t';";
        const char exp1[] = "var str='<scrip";
        const char exp2[] = "='";

        NORM_BAD_2(dat1, dat2, exp1, exp2, JSTokenizer::OPENING_TAG);
    }
    SECTION("< scr ipt")
    {
        const char dat1[] = "<";
        const char dat2[] = "scr";
        const char dat3[] = "ipt";
        const char exp1[] = "<";
        const char exp2[] = "<scr";
        const char exp3[] = "";

        NORM_BAD_3(dat1, dat2, dat3, exp1, exp2, exp3, JSTokenizer::OPENING_TAG);
    }
    SECTION("str='<sc rip t'")
    {
        const char dat1[] = "var str =\"<sc";
        const char dat2[] = "rip";
        const char dat3[] = "t\";";
        const char exp1[] = "var str=\"<sc";
        const char exp2[] = " str=\"<scrip";
        const char exp3[] = "=\"";

        NORM_BAD_3(dat1, dat2, dat3, exp1, exp2, exp3, JSTokenizer::OPENING_TAG);
    }
}

TEST_CASE("split in closing tag", "[JSNormalizer]")
{
    SECTION("< /script>")
    {
        const char dat1[] = "<";
        const char dat2[] = "/script>";
        const char exp1[] = "<";
        const char exp2[] = "";

        NORM_BAD_2(dat1, dat2, exp1, exp2, JSTokenizer::SCRIPT_ENDED);
    }
    SECTION("</script >")
    {
        const char dat1[] = "</script";
        const char dat2[] = ">";
        const char exp1[] = "</script";
        const char exp2[] = "";

        NORM_BAD_2(dat1, dat2, exp1, exp2, JSTokenizer::SCRIPT_ENDED);
    }
    SECTION("str='</ script>'")
    {
        const char dat1[] = "var str ='</";
        const char dat2[] = "script>';";
        const char exp1[] = "var str='</";
        const char exp2[] = "var str='";

        NORM_BAD_2(dat1, dat2, exp1, exp2, JSTokenizer::CLOSING_TAG);
    }
    SECTION("str='</scrip t>'")
    {
        const char dat1[] = "var str ='</scrip";
        const char dat2[] = "t>';";
        const char exp1[] = "var str='</scrip";
        const char exp2[] = "'";

        NORM_BAD_2(dat1, dat2, exp1, exp2, JSTokenizer::CLOSING_TAG);
    }
    SECTION("</ scr ipt>")
    {
        const char dat1[] = "</";
        const char dat2[] = "scr";
        const char dat3[] = "ipt>";
        const char exp1[] = "</";
        const char exp2[] = "</scr";
        const char exp3[] = "";

        NORM_BAD_3(dat1, dat2, dat3, exp1, exp2, exp3, JSTokenizer::SCRIPT_ENDED);
    }
    SECTION("str='</sc rip t>'")
    {
        const char dat1[] = "var str =\"</sc";
        const char dat2[] = "rip";
        const char dat3[] = "t>\";";
        const char exp1[] = "var str=\"</sc";
        const char exp2[] = " str=\"</scrip";
        const char exp3[] = "\"";

        NORM_BAD_3(dat1, dat2, dat3, exp1, exp2, exp3, JSTokenizer::CLOSING_TAG);
    }
}

TEST_CASE("split in string literal", "[JSNormalizer]")
{
    SECTION("\\ LF")
    {
        const char dat1[] = "var str =\"any\\";
        const char dat2[] = "\none\";";
        const char exp1[] = "var str=\"any\\";
        const char exp2[] = " str=\"anyone\";";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("\\ CR")
    {
        const char dat1[] = "var str =\"any\\";
        const char dat2[] = "\rone\";";
        const char exp1[] = "var str=\"any\\";
        const char exp2[] = " str=\"anyone\";";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("\\CR LF")
    {
        const char dat1[] = "var str =\"any\\\r";
        const char dat2[] = "\none\";";
        const char exp1[] = "var str=\"any";
        const char exp2[] = " str=\"anyone\";";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("\\ CRLF")
    {
        const char dat1[] = "var str =\"any\\";
        const char dat2[] = "\r\none\";";
        const char exp1[] = "var str=\"any\\";
        const char exp2[] = " str=\"anyone\";";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("\\ \"")
    {
        const char dat1[] = "var str =\"any\\";
        const char dat2[] = "\"one\";";
        const char exp1[] = "var str=\"any\\";
        const char exp2[] = " str=\"any\\\"one\";";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("\\ \'")
    {
        const char dat1[] = "var str =\"any\\";
        const char dat2[] = "\'one\";";
        const char exp1[] = "var str=\"any\\";
        const char exp2[] = " str=\"any\\\'one\";";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("\\ u1234tx")
    {
        const char dat1[] = "var str =\"any\\";
        const char dat2[] = "u1234tx\";";
        const char exp1[] = "var str=\"any\\";
        const char exp2[] = " str=\"any\\u1234tx\";";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("\\u 1234tx")
    {
        const char dat1[] = "var str =\"any\\u";
        const char dat2[] = "1234tx\";";
        const char exp1[] = "var str=\"any\\u";
        const char exp2[] = "=\"any\\u1234tx\";";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
}

TEST_CASE("split in identifier", "[JSNormalizer]")
{
    SECTION("abc def")
    {
        const char dat1[] = "var abc";
        const char dat2[] = "def = 5";
        const char exp1[] = "var abc";
        const char exp2[] = "var abcdef=5";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("abc def")
    {
        const char dat1[] = "var abc";
        const char dat2[] = "def = 5";
        const char exp1[] = "var abc";
        const char exp2[] = "var abcdef=5";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("long identifier")
    {
        const char dat1[] = "var res = something + long_id_starts_here";
        const char dat2[] = "_long_id_ends_here;";
        const char exp1[] = "var res=something+long_id_starts_here";
        const char exp2[] = "=something+long_id_starts_here_long_id_ends_here;";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
}

TEST_CASE("split in keyword", "[JSNormalizer]")
{
    SECTION("finally")
    {
        const char dat1[] = "\nfin";
        const char dat2[] = "ally;";
        const char exp1[] = "fin";
        const char exp2[] = "finally;";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("in")
    {
        const char dat1[] = "i";
        const char dat2[] = "n";
        const char exp1[] = "i";
        const char exp2[] = "in";

        NORMALIZE_2(dat1, dat2, exp1, exp2);
    }
    SECTION("instanceof")
    {
        const char dat1[] = "in";
        const char dat2[] = "stance";
        const char dat3[] = "of";
        const char exp1[] = "in";
        const char exp2[] = "instance";
        const char exp3[] = "instanceof";

        NORMALIZE_3(dat1, dat2, dat3, exp1, exp2, exp3);
    }
}

TEST_CASE("memcap", "[JSNormalizer]")
{
    SECTION("3 tokens")
    {
        const char dat1[] = "var abc=in";
        const char dat2[] = "put;";
        const char exp1[] = "var abc=in";
        const char exp2[] = " abc=input;";

        NORM_LIMITED(6, dat1, dat2, exp1, exp2);
    }
    SECTION("2 tokens and a half")
    {
        const char dat1[] = "var abc=in";
        const char dat2[] = "put;";
        const char exp1[] = "var abc=in";
        const char exp2[] = " c=input;";

        NORM_LIMITED(4, dat1, dat2, exp1, exp2);
    }
    SECTION("1 token")
    {
        const char dat1[] = "var abc=in";
        const char dat2[] = "put;";
        const char exp1[] = "var abc=in";
        const char exp2[] = "input;";

        NORM_LIMITED(2, dat1, dat2, exp1, exp2);
    }
    SECTION("a half")
    {
        const char dat1[] = "var abc=extract";
        const char dat2[] = "// just a comment\n";
        const char exp1[] = "var abc=extract";
        const char exp2[] = "tract";

        NORM_LIMITED(5, dat1, dat2, exp1, exp2);
    }
}

#endif // CATCH_TEST_BUILD

// Benchmark tests

#ifdef BENCHMARK_TEST

#define UNLIM_DEPTH -1

static constexpr const char* s_closing_tag = "</script>";

#define MAKE_INPUT(src, src_len, start, mid, end, depth) \
    std::string input_##src(start); \
    input_##src.append(depth - strlen(start) - strlen(end) - strlen(s_closing_tag), mid); \
    input_##src.append(end, strlen(end)); \
    input_##src.append(s_closing_tag, strlen(s_closing_tag)); \
    const char* src = input_##src.c_str(); \
    size_t src_len = input_##src.size()

TEST_CASE("benchmarking - ::normalize() - literals", "[JSNormalizer]")
{
    JSIdentifierCtxTest ident_ctx;
    JSNormalizer normalizer(ident_ctx, UNLIM_DEPTH, MAX_TEMPLATE_NESTNIG);
    char dst[DEPTH];

    MAKE_INPUT(src_ws, src_ws_len, "", ' ', "", DEPTH);
    MAKE_INPUT(src_bcomm, src_bcomm_len, "/*", ' ', "*/", DEPTH);
    MAKE_INPUT(src_dqstr, src_dqstr_len, "\"", ' ', "\"", DEPTH);

    BENCHMARK("memcpy - whitespaces - 65535 bytes")
    {
        return memcpy(dst, src_ws, src_ws_len);
    };
    BENCHMARK("whitespaces - 65535 bytes")
    {
        normalizer.rewind_output();
        return normalizer.normalize(src_ws, src_ws_len);
    };
    BENCHMARK("block comment - 65535 bytes")
    {
        normalizer.rewind_output();
        return normalizer.normalize(src_bcomm, src_bcomm_len);
    };
    BENCHMARK("double quotes string - 65535 bytes")
    {
        normalizer.rewind_output();
        return normalizer.normalize(src_dqstr, src_dqstr_len);
    };

    constexpr size_t depth_8k = 8192;

    MAKE_INPUT(src_ws_8k, src_ws_len_8k, "", ' ', "", depth_8k);
    MAKE_INPUT(src_bcomm_8k, src_bcomm_len_8k, "/*", ' ', "*/", depth_8k);
    MAKE_INPUT(src_dqstr_8k, src_dqstr_len_8k, "\"", ' ', "\"", depth_8k);

    BENCHMARK("memcpy - whitespaces - 8192 bytes")
    {
        return memcpy(dst, src_ws_8k, src_ws_len_8k);
    };
    BENCHMARK("whitespaces - 8192 bytes")
    {
        normalizer.rewind_output();
        return normalizer.normalize(src_ws_8k, src_ws_len_8k);
    };
    BENCHMARK("block comment - 8192 bytes")
    {
        normalizer.rewind_output();
        return normalizer.normalize(src_bcomm_8k, src_bcomm_len_8k);
    };
    BENCHMARK("double quotes string - 8192 bytes")
    {
        normalizer.rewind_output();
        return normalizer.normalize(src_dqstr_8k, src_dqstr_len_8k);
    };
}

TEST_CASE("benchmarking - ::normalize() - identifiers")
{
    // around 11 000 identifiers
    std::string input;
    for (int it = 0; it < DEPTH; ++it)
        input.append("n" + std::to_string(it) + " ");

    input.resize(DEPTH - strlen(s_closing_tag));
    input.append(s_closing_tag, strlen(s_closing_tag));
    const char* src = input.c_str();
    size_t src_len = input.size();

    JSIdentifierCtxTest ident_ctx_mock;
    JSNormalizer normalizer_wo_ident(ident_ctx_mock, UNLIM_DEPTH, MAX_TEMPLATE_NESTNIG);

    BENCHMARK("without substitution")
    {
        normalizer_wo_ident.rewind_output();
        return normalizer_wo_ident.normalize(src, src_len);
    };

    JSIdentifierCtx ident_ctx(DEPTH);
    JSNormalizer normalizer_w_ident(ident_ctx, UNLIM_DEPTH, MAX_TEMPLATE_NESTNIG);

    BENCHMARK("with substitution")
    {
        normalizer_w_ident.rewind_output();
        return normalizer_w_ident.normalize(src, src_len);
    };
}

#endif // BENCHMARK_TEST
