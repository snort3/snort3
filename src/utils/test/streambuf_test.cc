//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "catch/catch.hpp"

#include <cstring>
#include <iostream>
#include <vector>

#include "utils/streambuf.h"

using namespace snort;
using namespace std;

#define ACT_SIZE 1024
#define EXP_SIZE 4096

#define EXP_AVAIL1(b, exp, len, off)            \
    {                                           \
        auto avail = (b).in_avail();            \
        CHECK(avail == (len) - (off));          \
                                                \
        char act[ACT_SIZE];                     \
        auto n = (b).sgetn(act, (len));         \
        REQUIRE(n == (len) - (off));            \
        CHECK(!memcmp((exp) + (off), act, n));  \
    }

#define EXP_AVAIL2(b, exp, len, off, len_1c)    \
    {                                           \
        auto avail = (b).in_avail();            \
        if ((off) < (len_1c))                   \
            CHECK(avail == (len_1c) - (off));   \
        else                                    \
            CHECK(avail == (len) - (off));      \
                                                \
        char act[ACT_SIZE];                     \
        auto n = (b).sgetn(act, (len));         \
        REQUIRE(n == (len) - (off));            \
        CHECK(!memcmp((exp) + (off), act, n));  \
    }

#define EXP_AVAILn(b, exp, len, off)            \
    {                                           \
        char act[ACT_SIZE];                     \
        auto n = (b).sgetn(act, (len));         \
        REQUIRE(n == (len) - (off));            \
        CHECK(!memcmp((exp) + (off), act, n));  \
    }

#define EXP_RES(b, exp, exp_len, exp_mem_size)                          \
    {                                                                   \
        auto d1_len = (b).data_len();                                   \
        auto d1 = (b).data();                                           \
        streamsize act_len;                                             \
        const char* act = (b).take_data(act_len);                       \
        auto d2_len = (b).data_len();                                   \
        auto d2 = (b).data();                                           \
                                                                        \
        CHECK(d1 == act);                                               \
        CHECK(d1_len == act_len);                                       \
        CHECK(d2 == nullptr);                                           \
        CHECK(d2_len == 0);                                             \
                                                                        \
        CHECK((exp_mem_size) == act_len);                               \
        REQUIRE((exp_len) <= act_len);                                  \
        CHECK(!memcmp((exp), act, (exp_len)));                          \
        delete[] act;                                                   \
    }

#define EXP_IN(s, exp, act, len)                                        \
    {                                                                   \
        CHECK(true == (s).good());                                      \
        REQUIRE((len) == (s).tellg());                                  \
        CHECK(!memcmp((exp), (act), (len)));                            \
    }

#define EOF_IN(s, exp, act, len)                                        \
    {                                                                   \
        CHECK(true == (s).eof());                                       \
        (s).clear();                                                    \
        REQUIRE((len) == (s).tellg());                                  \
        CHECK(!memcmp((exp), (act), (len)));                            \
    }

#define EXP_OUT(s, exp, exp_len)                                        \
    {                                                                   \
        CHECK(false == (s).fail());                                     \
        CHECK(false == (s).bad());                                      \
        (s).clear();                                                    \
        CHECK((exp_len) == (s).tellp());                                \
                                                                        \
        ostreambuf_infl* b = reinterpret_cast<ostreambuf_infl*>((s).rdbuf()); \
        auto act = b->data();                                           \
        auto act_len = b->data_len();                                   \
                                                                        \
        REQUIRE((exp_len) == act_len);                                  \
        CHECK(!memcmp((exp), act, (exp_len)));                          \
    }

#define EOF_OUT(s, exp, exp_len)                                        \
    {                                                                   \
        CHECK(true == (s).fail());                                      \
        CHECK(true == (s).bad());                                       \
        (s).clear();                                                    \
        CHECK((exp_len) == (s).tellp());                                \
                                                                        \
        ostreambuf_infl* b = reinterpret_cast<ostreambuf_infl*>((s).rdbuf()); \
        auto act = b->data();                                           \
        auto act_len = b->data_len();                                   \
                                                                        \
        REQUIRE((exp_len) == act_len);                                  \
        CHECK(!memcmp((exp), act, (exp_len)));                          \
    }

#define BYTES_READ(s, b)                                           \
    ((s).clear(),                                                  \
     std::max((std::streamsize)(s).tellg(),                        \
              (std::streamsize)(b).last_chunk_offset())            \
     - (b).last_chunk_offset())

TEST_CASE("input buffer - basic one source", "[Stream buffers]")
{
    const char* exp = "Early bird gets a corn.";
    const int len = strlen(exp);
    char dat[] = "Early bird gets a corn.";

    SECTION("no data")
    {
        istreambuf_glue b;

        int avail_1 = b.in_avail();
        int c = b.sgetc();
        int avail_2 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK(c == EOF);
        CHECK((avail_1 == -1));
        CHECK((avail_2 == -1));
        CHECK((off_b == -1));
        CHECK((off_c == -1));
        CHECK((off_e == -1));
    }

    SECTION("get char")
    {
        istreambuf_glue b;

        b.pubsetbuf(dat, len);

        int avail_1 = b.in_avail();
        int c = b.sgetc();
        int avail_2 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((c == 'E'));
        CHECK((avail_1 == len));
        CHECK((avail_2 == len));
        CHECK(off_b == 0);
        CHECK(off_c == 0);
        CHECK((off_e == len));
    }

    SECTION("get char and bump")
    {
        istreambuf_glue b;

        b.pubsetbuf(dat, len);

        int avail_1 = b.in_avail();
        int c = b.sbumpc();
        int avail_2 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((c == 'E'));
        CHECK((avail_1 == len));
        CHECK((avail_2 == (len - 1)));
        CHECK(off_b == 0);
        CHECK(off_c == 1);
        CHECK((off_e == len));
    }

    SECTION("advance and get char")
    {
        istreambuf_glue b;

        b.pubsetbuf(dat, len);

        int avail_1 = b.in_avail();
        int c = b.snextc();
        int avail_2 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((c == 'a'));
        CHECK((avail_1 == len));
        CHECK((avail_2 == (len - 1)));
        CHECK(off_b == 0);
        CHECK(off_c == 1);
        CHECK((off_e == len));
    }

    SECTION("get chars")
    {
        char act[ACT_SIZE];
        istreambuf_glue b;

        b.pubsetbuf(dat, len);

        int avail_1 = b.in_avail();
        int nread_1 = b.sgetn(act, 10);
        int avail_2 = b.in_avail();
        int nread_2 = b.sgetn(act + 10, 10);
        int avail_3 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((nread_1 == 10));
        CHECK((nread_2 == 10));
        CHECK((avail_1 == len));
        CHECK((avail_2 == (len - 10)));
        CHECK((avail_3 == (len - 20)));
        CHECK(off_b == 0);
        CHECK((off_c == 20));
        CHECK((off_e == len));
        CHECK(!memcmp(exp, act, 20));
    }

    SECTION("get chars EOF")
    {
        char act[ACT_SIZE];
        istreambuf_glue b;

        b.pubsetbuf(dat, len);

        int avail_1 = b.in_avail();
        int nread_1 = b.sgetn(act, 10);
        int avail_2 = b.in_avail();
        int nread_2 = b.sgetn(act + 10, 10);
        int avail_3 = b.in_avail();
        int nread_3 = b.sgetn(act + 20, 10);
        int avail_4 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((nread_1 == 10));
        CHECK((nread_2 == 10));
        CHECK((nread_3 == 3));
        CHECK((avail_1 == len));
        CHECK((avail_2 == (len - 10)));
        CHECK((avail_3 == (len - 20)));
        CHECK(avail_4 == 0);
        CHECK(off_b == 0);
        CHECK((off_c == 23));
        CHECK((off_e == len));
        CHECK(!memcmp(exp, act, len));
    }

    SECTION("put char back")
    {
        istreambuf_glue b;

        b.pubsetbuf(dat, len);

        int off_o = b.pubseekoff(5, ios_base::beg, ios_base::in);
        int avail_1 = b.in_avail();
        int c = b.sungetc();
        int avail_2 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((c == 'y'));
        CHECK((avail_1 == (len - 5)));
        CHECK((avail_2 == (len - 4)));
        CHECK((off_o == 5));
        CHECK(off_b == 0);
        CHECK((off_c == 4));
        CHECK((off_e == len));
    }

    SECTION("put another char back")
    {
        istreambuf_glue b;

        b.pubsetbuf(dat, len);

        int off_o = b.pubseekoff(5, ios_base::beg, ios_base::in);
        int avail_1 = b.in_avail();
        int c1 = b.sputbackc(' ');
        int c2 = b.sputbackc('y');
        int avail_2 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((c1 == -1));
        CHECK((c2 == 'y'));
        CHECK((avail_1 == (len - 5)));
        CHECK((avail_2 == (len - 4)));
        CHECK((off_o == 5));
        CHECK(off_b == 0);
        CHECK((off_c == 4));
        CHECK((off_e == len));
    }
}

TEST_CASE("input buffer - basic two sources", "[Stream buffers]")
{
    const char* exp = "Early bird gets a corn.";
    const int len = strlen(exp);
    char dat1[] = "Early bird";
    char dat2[] = " gets a corn.";
    const int dat1_len = strlen(dat1);
    const int dat2_len = strlen(dat2);

    SECTION("get char")
    {
        istreambuf_glue b;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        int avail_1 = b.in_avail();
        int c = b.sgetc();
        int avail_2 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((c == 'E'));
        CHECK(avail_1 == dat1_len);
        CHECK(avail_2 == dat1_len);
        CHECK(off_b == 0);
        CHECK(off_c == 0);
        CHECK((off_e == len));
    }

    SECTION("get char and bump")
    {
        istreambuf_glue b;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        int avail_1 = b.in_avail();
        int c = b.sbumpc();
        int avail_2 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((c == 'E'));
        CHECK(avail_1 == dat1_len);
        CHECK(avail_2 == dat1_len - 1);
        CHECK(off_b == 0);
        CHECK(off_c == 1);
        CHECK((off_e == len));
    }

    SECTION("advance and get char")
    {
        istreambuf_glue b;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        int avail_1 = b.in_avail();
        int c = b.snextc();
        int avail_2 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((c == 'a'));
        CHECK(avail_1 == dat1_len);
        CHECK(avail_2 == dat1_len - 1);
        CHECK(off_b == 0);
        CHECK(off_c == 1);
        CHECK((off_e == len));
    }

    SECTION("get chars")
    {
        char act[ACT_SIZE];
        istreambuf_glue b;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        int avail_1 = b.in_avail();
        int nread_1 = b.sgetn(act, 10);
        int avail_2 = b.in_avail();
        int nread_2 = b.sgetn(act + 10, 10);
        int avail_3 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((nread_1 == 10));
        CHECK((nread_2 == 10));
        CHECK(avail_1 == dat1_len);
        CHECK((avail_2 == (len - 10)));
        CHECK((avail_3 == (len - 20)));
        CHECK(off_b == 0);
        CHECK((off_c == 20));
        CHECK((off_e == len));
        CHECK(!memcmp(exp, act, 20));
    }

    SECTION("get chars EOF")
    {
        char act[ACT_SIZE];
        istreambuf_glue b;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        int avail_1 = b.in_avail();
        int nread_1 = b.sgetn(act, 10);
        int avail_2 = b.in_avail();
        int nread_2 = b.sgetn(act + 10, 10);
        int avail_3 = b.in_avail();
        int nread_3 = b.sgetn(act + 20, 10);
        int avail_4 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((nread_1 == 10));
        CHECK((nread_2 == 10));
        CHECK((nread_3 == 3));
        CHECK(avail_1 == dat1_len);
        CHECK((avail_2 == (len - 10)));
        CHECK((avail_3 == (len - 20)));
        CHECK(avail_4 == 0);
        CHECK(off_b == 0);
        CHECK((off_c == 23));
        CHECK((off_e == len));
        CHECK(!memcmp(exp, act, len));
    }

    SECTION("put char back")
    {
        istreambuf_glue b;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        int off_o = b.pubseekoff(5, ios_base::beg, ios_base::in);
        int avail_1 = b.in_avail();
        int c = b.sungetc();
        int avail_2 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((c == 'y'));
        CHECK(avail_1 == dat1_len - 5);
        CHECK(avail_2 == dat1_len - 4);
        CHECK((off_o == 5));
        CHECK(off_b == 0);
        CHECK((off_c == 4));
        CHECK((off_e == len));
    }

    SECTION("put another char back")
    {
        istreambuf_glue b;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        int off_o = b.pubseekoff(5, ios_base::beg, ios_base::in);
        int avail_1 = b.in_avail();
        int c1 = b.sputbackc(' ');
        int c2 = b.sputbackc('y');
        int avail_2 = b.in_avail();
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((c1 == -1));
        CHECK((c2 == 'y'));
        CHECK(avail_1 == dat1_len - 5);
        CHECK(avail_2 == dat1_len - 4);
        CHECK((off_o == 5));
        CHECK(off_b == 0);
        CHECK((off_c == 4));
        CHECK((off_e == len));
    }
}

TEST_CASE("input buffer - buffer management", "[Stream buffers]")
{
    const char* exp = "Early bird gets a corn.";
    const int len = strlen(exp);
    char dat[] = "Early bird gets a corn."; // cppcheck-suppress variableScope
    char dat1[] = "Early ";
    char dat2[] = "bird ";
    char dat3[] = "gets ";
    char dat4[] = "a corn.";
    const int dat1_len = strlen(dat1);
    const int dat2_len = strlen(dat2);
    const int dat3_len = strlen(dat3);
    const int dat4_len = strlen(dat4);

    SECTION("sync")
    {
        istreambuf_glue b1, b2;

        b1.pubsetbuf(dat, len);
        b2.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        int r1 = b1.pubsync();
        int r2 = b2.pubsync();

        CHECK((r1 == -1));
        CHECK((r2 == -1));
    }

    SECTION("chain of buffers")
    {
        istreambuf_glue b;

        b.pubsetbuf(nullptr, 0);

        b.pubsetbuf(dat1, dat1_len);
        EXP_AVAILn(b, exp, dat1_len, 0);
        b.pubsetbuf(dat2, dat2_len);
        EXP_AVAILn(b, exp + dat1_len, dat2_len, 0);

        b.pubsetbuf(nullptr, 0);

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);
        EXP_AVAILn(b, exp, dat1_len + dat2_len, 0);
        b.pubsetbuf(dat3, dat3_len)->pubsetbuf(dat4, dat4_len);
        EXP_AVAILn(b, exp + dat1_len + dat2_len, dat3_len + dat4_len, 0);

        b.pubsetbuf(nullptr, 0);

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len)
            ->pubsetbuf(dat3, dat3_len)->pubsetbuf(dat4, dat4_len);
        EXP_AVAILn(b, exp, len, 0);
    }
}

TEST_CASE("input buffer - offset one source", "[Stream buffers]")
{
    const char* exp = "Early bird gets a corn.";
    const int len = strlen(exp);
    const int len1d3 = strlen(exp) * 1 / 3;
    const int len2d3 = len - len1d3;
    char dat[] = "Early bird gets a corn.";

    SECTION("no data")
    {
        istreambuf_glue b;

        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);

        CHECK((off_b == -1));
        CHECK((off_c == -1));
        CHECK((off_e == -1));
    }

    SECTION("wrong argument")
    {
        istreambuf_glue b;

        b.pubsetbuf(dat, len);

        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::out);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::out);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::out);
        int off_a = b.pubseekoff(0, static_cast<std::ios_base::seekdir>(0x5a5a), ios_base::in);

        CHECK((off_b == -1));
        CHECK((off_c == -1));
        CHECK((off_e == -1));
        CHECK((off_a == -1));
    }

    SECTION("begin")
    {
        istreambuf_glue b;
        int off;

        b.pubsetbuf(dat, len);

        off = b.pubseekoff(0 - len - len, ios_base::beg, ios_base::in);
        CHECK(off == 0);
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0 + len + len, ios_base::beg, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0, ios_base::beg, ios_base::in);
        CHECK(off == 0);
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0 - 1, ios_base::beg, ios_base::in);
        CHECK(off == 0);
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0 + 1, ios_base::beg, ios_base::in);
        CHECK(off == 1);
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0 + len1d3, ios_base::beg, ios_base::in);
        CHECK((off == len1d3));
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0 + len2d3, ios_base::beg, ios_base::in);
        CHECK((off == len2d3));
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0 + len - 1, ios_base::beg, ios_base::in);
        CHECK((off == (len - 1)));
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0 + len, ios_base::beg, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL1(b, exp, len, off);
    }

    SECTION("end")
    {
        istreambuf_glue b;
        int off;

        b.pubsetbuf(dat, len);

        off = b.pubseekoff(0 - len - len, ios_base::end, ios_base::in);
        CHECK(off == 0);
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0 + len + len, ios_base::end, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0, ios_base::end, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0 - 1, ios_base::end, ios_base::in);
        CHECK((off == (len - 1)));
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0 + 1, ios_base::end, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0 - len1d3, ios_base::end, ios_base::in);
        CHECK((off == len2d3));
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0 - len2d3, ios_base::end, ios_base::in);
        CHECK((off == len1d3));
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0 - len + 1, ios_base::end, ios_base::in);
        CHECK(off == 1);
        EXP_AVAIL1(b, exp, len, off);

        off = b.pubseekoff(0 - len, ios_base::end, ios_base::in);
        CHECK(off == 0);
        EXP_AVAIL1(b, exp, len, off);
    }

    SECTION("current 1/3")
    {
        istreambuf_glue b;
        int off;

        b.pubsetbuf(dat, len);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 - len - len, ios_base::cur, ios_base::in);
        CHECK(off == 0);
        EXP_AVAIL1(b, exp, len, off);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len + len, ios_base::cur, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL1(b, exp, len, off);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0, ios_base::cur, ios_base::in);
        CHECK((off == len1d3));
        EXP_AVAIL1(b, exp, len, off);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 - 1, ios_base::cur, ios_base::in);
        CHECK((off == (len1d3 - 1)));
        EXP_AVAIL1(b, exp, len, off);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + 1, ios_base::cur, ios_base::in);
        CHECK((off == (len1d3 + 1)));
        EXP_AVAIL1(b, exp, len, off);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len1d3, ios_base::cur, ios_base::in);
        CHECK((off == (len1d3 + len1d3)));
        EXP_AVAIL1(b, exp, len, off);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len2d3, ios_base::cur, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL1(b, exp, len, off);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len, ios_base::cur, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL1(b, exp, len, off);
    }

    SECTION("current 2/3")
    {
        istreambuf_glue b;
        int off;

        b.pubsetbuf(dat, len);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 - len - len, ios_base::cur, ios_base::in);
        CHECK(off == 0);
        EXP_AVAIL1(b, exp, len, off);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len + len, ios_base::cur, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL1(b, exp, len, off);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0, ios_base::cur, ios_base::in);
        CHECK((off == len2d3));
        EXP_AVAIL1(b, exp, len, off);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 - 1, ios_base::cur, ios_base::in);
        CHECK((off == (len2d3 - 1)));
        EXP_AVAIL1(b, exp, len, off);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + 1, ios_base::cur, ios_base::in);
        CHECK((off == (len2d3 + 1)));
        EXP_AVAIL1(b, exp, len, off);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len1d3, ios_base::cur, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL1(b, exp, len, off);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len2d3, ios_base::cur, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL1(b, exp, len, off);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len, ios_base::cur, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL1(b, exp, len, off);
    }
}

TEST_CASE("input buffer - offset two sources", "[Stream buffers]")
{
    const char* exp = "Early bird gets a corn.";
    const int len = strlen(exp);
    const int len1d3 = strlen(exp) * 1 / 3;
    const int len2d3 = len - len1d3;
    char dat1[] = "Early bird";
    char dat2[] = " gets a corn.";
    const int dat1_len = strlen(dat1);
    const int dat2_len = strlen(dat2);

    SECTION("wrong buffer")
    {
        istreambuf_glue b;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::out);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::out);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::out);

        CHECK((off_b == -1));
        CHECK((off_c == -1));
        CHECK((off_e == -1));
    }

    SECTION("begin")
    {
        istreambuf_glue b;
        int off;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        off = b.pubseekoff(0 - len - len, ios_base::beg, ios_base::in);
        CHECK(off == 0);
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0 + len + len, ios_base::beg, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0, ios_base::beg, ios_base::in);
        CHECK(off == 0);
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0 - 1, ios_base::beg, ios_base::in);
        CHECK(off == 0);
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0 + 1, ios_base::beg, ios_base::in);
        CHECK(off == 1);
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0 + len1d3, ios_base::beg, ios_base::in);
        CHECK((off == len1d3));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0 + len2d3, ios_base::beg, ios_base::in);
        CHECK((off == len2d3));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0 + len - 1, ios_base::beg, ios_base::in);
        CHECK((off == (len - 1)));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0 + len, ios_base::beg, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL2(b, exp, len, off, dat1_len);
    }

    SECTION("end")
    {
        istreambuf_glue b;
        int off;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        off = b.pubseekoff(0 - len - len, ios_base::end, ios_base::in);
        CHECK(off == 0);
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0 + len + len, ios_base::end, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0, ios_base::end, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0 - 1, ios_base::end, ios_base::in);
        CHECK((off == (len - 1)));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0 + 1, ios_base::end, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0 - len1d3, ios_base::end, ios_base::in);
        CHECK((off == len2d3));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0 - len2d3, ios_base::end, ios_base::in);
        CHECK((off == len1d3));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0 - len + 1, ios_base::end, ios_base::in);
        CHECK(off == 1);
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        off = b.pubseekoff(0 - len, ios_base::end, ios_base::in);
        CHECK(off == 0);
        EXP_AVAIL2(b, exp, len, off, dat1_len);
    }

    SECTION("current 1/3")
    {
        istreambuf_glue b;
        int off;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 - len - len, ios_base::cur, ios_base::in);
        CHECK(off == 0);
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len + len, ios_base::cur, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0, ios_base::cur, ios_base::in);
        CHECK((off == len1d3));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 - 1, ios_base::cur, ios_base::in);
        CHECK((off == (len1d3 - 1)));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + 1, ios_base::cur, ios_base::in);
        CHECK((off == (len1d3 + 1)));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len1d3, ios_base::cur, ios_base::in);
        CHECK((off == (len1d3 + len1d3)));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len2d3, ios_base::cur, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len, ios_base::cur, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL2(b, exp, len, off, dat1_len);
    }

    SECTION("current 2/3")
    {
        istreambuf_glue b;
        int off;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 - len - len, ios_base::cur, ios_base::in);
        CHECK(off == 0);
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len + len, ios_base::cur, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0, ios_base::cur, ios_base::in);
        CHECK((off == len2d3));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 - 1, ios_base::cur, ios_base::in);
        CHECK((off == (len2d3 - 1)));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + 1, ios_base::cur, ios_base::in);
        CHECK((off == (len2d3 + 1)));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len1d3, ios_base::cur, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len2d3, ios_base::cur, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL2(b, exp, len, off, dat1_len);

        b.pubseekoff(len2d3, ios_base::beg, ios_base::in);
        off = b.pubseekoff(0 + len, ios_base::cur, ios_base::in);
        CHECK((off == len));
        EXP_AVAIL2(b, exp, len, off, dat1_len);
    }
}

TEST_CASE("input buffer - positioning one source", "[Stream buffers]")
{
    const char* exp = "Early bird gets a corn.";
    const int len = strlen(exp);
    const int len1d3 = strlen(exp) * 1 / 3;
    const int len2d3 = len - len1d3;
    char dat[] = "Early bird gets a corn.";

    SECTION("no data")
    {
        istreambuf_glue b;

        int pos_c = b.pubseekpos(len / 2, ios_base::in);
        int pos_b = b.pubseekpos(0,       ios_base::in);
        int pos_e = b.pubseekpos(len,     ios_base::in);

        CHECK((pos_b == -1));
        CHECK((pos_c == -1));
        CHECK((pos_e == -1));
    }

    SECTION("wrong buffer")
    {
        istreambuf_glue b;

        b.pubsetbuf(dat, len);

        int pos_c = b.pubseekpos(len / 2, ios_base::out);
        int pos_b = b.pubseekpos(0,       ios_base::out);
        int pos_e = b.pubseekpos(len,     ios_base::out);

        CHECK((pos_b == -1));
        CHECK((pos_c == -1));
        CHECK((pos_e == -1));
    }

    SECTION("out of range")
    {
        istreambuf_glue b;
        int pos;

        b.pubsetbuf(dat, len);

        pos = b.pubseekpos(0 - len, ios_base::in);
        CHECK(pos == 0);
        EXP_AVAIL1(b, exp, len, pos);

        pos = b.pubseekpos(len + len, ios_base::in);
        CHECK((pos == len));
        EXP_AVAIL1(b, exp, len, pos);
    }

    SECTION("on the edge")
    {
        istreambuf_glue b;
        int pos;

        b.pubsetbuf(dat, len);

        pos = b.pubseekpos(0, ios_base::in);
        CHECK(pos == 0);
        EXP_AVAIL1(b, exp, len, pos);

        pos = b.pubseekpos(0 - 1, ios_base::in);
        CHECK(pos == 0);
        EXP_AVAIL1(b, exp, len, pos);

        pos = b.pubseekpos(0 + 1, ios_base::in);
        CHECK(pos == 1);
        EXP_AVAIL1(b, exp, len, pos);

        pos = b.pubseekpos(len, ios_base::in);
        CHECK((pos == len));
        EXP_AVAIL1(b, exp, len, pos);

        pos = b.pubseekpos(len - 1, ios_base::in);
        CHECK((pos == (len - 1)));
        EXP_AVAIL1(b, exp, len, pos);

        pos = b.pubseekpos(len + 1, ios_base::in);
        CHECK((pos == len));
        EXP_AVAIL1(b, exp, len, pos);
    }

    SECTION("in range")
    {
        istreambuf_glue b;
        int pos;

        b.pubsetbuf(dat, len);

        pos = b.pubseekpos(len1d3, ios_base::in);
        CHECK((pos == len1d3));
        EXP_AVAIL1(b, exp, len, pos);

        pos = b.pubseekpos(len2d3, ios_base::in);
        CHECK((pos == len2d3));
        EXP_AVAIL1(b, exp, len, pos);
    }
}

TEST_CASE("input buffer - positioning two sources", "[Stream buffers]")
{
    const char* exp = "Early bird gets a corn.";
    const int len = strlen(exp);
    const int len1d3 = strlen(exp) * 1 / 3;
    const int len2d3 = len - len1d3;
    char dat1[] = "Early bird";
    char dat2[] = " gets a corn.";
    const int dat1_len = strlen(dat1);
    const int dat2_len = strlen(dat2);

    SECTION("wrong buffer")
    {
        istreambuf_glue b;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        int pos_c = b.pubseekpos(len / 2, ios_base::out);
        int pos_b = b.pubseekpos(0,       ios_base::out);
        int pos_e = b.pubseekpos(len,     ios_base::out);

        CHECK((pos_b == -1));
        CHECK((pos_c == -1));
        CHECK((pos_e == -1));
    }

    SECTION("out of range")
    {
        istreambuf_glue b;
        int pos;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        pos = b.pubseekpos(0 - len, ios_base::in);
        CHECK(pos == 0);
        EXP_AVAIL2(b, exp, len, pos, dat1_len);

        pos = b.pubseekpos(len + len, ios_base::in);
        CHECK((pos == len));
        EXP_AVAIL2(b, exp, len, pos, dat1_len);
    }

    SECTION("on the edge")
    {
        istreambuf_glue b;
        int pos;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        pos = b.pubseekpos(0, ios_base::in);
        CHECK(pos == 0);
        EXP_AVAIL2(b, exp, len, pos, dat1_len);

        pos = b.pubseekpos(0 - 1, ios_base::in);
        CHECK(pos == 0);
        EXP_AVAIL2(b, exp, len, pos, dat1_len);

        pos = b.pubseekpos(0 + 1, ios_base::in);
        CHECK(pos == 1);
        EXP_AVAIL2(b, exp, len, pos, dat1_len);

        pos = b.pubseekpos(len, ios_base::in);
        CHECK((pos == len));
        EXP_AVAIL2(b, exp, len, pos, dat1_len);

        pos = b.pubseekpos(len - 1, ios_base::in);
        CHECK((pos == (len - 1)));
        EXP_AVAIL2(b, exp, len, pos, dat1_len);

        pos = b.pubseekpos(len + 1, ios_base::in);
        CHECK((pos == len));
        EXP_AVAIL2(b, exp, len, pos, dat1_len);
    }

    SECTION("in range")
    {
        istreambuf_glue b;
        int pos;

        b.pubsetbuf(dat1, dat1_len)->pubsetbuf(dat2, dat2_len);

        pos = b.pubseekpos(len1d3, ios_base::in);
        CHECK((pos == len1d3));
        EXP_AVAIL2(b, exp, len, pos, dat1_len);

        pos = b.pubseekpos(len2d3, ios_base::in);
        CHECK((pos == len2d3));
        EXP_AVAIL2(b, exp, len, pos, dat1_len);

        pos = b.pubseekpos(dat1_len, ios_base::in);
        CHECK(pos == dat1_len);
        EXP_AVAIL2(b, exp, len, pos, dat1_len);

        pos = b.pubseekpos(dat1_len + 1, ios_base::in);
        CHECK(pos == dat1_len + 1);
        EXP_AVAIL2(b, exp, len, pos, dat1_len);

        pos = b.pubseekpos(dat1_len - 1, ios_base::in);
        CHECK(pos == dat1_len - 1);
        EXP_AVAIL2(b, exp, len, pos, dat1_len);

        pos = b.pubseekpos(dat1_len + 2, ios_base::in);
        CHECK(pos == dat1_len + 2);
        EXP_AVAIL2(b, exp, len, pos, dat1_len);

        pos = b.pubseekpos(dat1_len - 2, ios_base::in);
        CHECK(pos == dat1_len - 2);
        EXP_AVAIL2(b, exp, len, pos, dat1_len);
    }
}

TEST_CASE("input stream - one source", "[Stream buffers]")
{
    const char* exp = "Early bird gets a corn.";
    const int len = strlen(exp);
    char dat[] = "Early bird gets a corn.";

    SECTION("no data")
    {
        char act[ACT_SIZE];
        istreambuf_glue b;
        istream s(&b);

        s.read(act, sizeof(act));

        CHECK(true == s.eof());
        CHECK(-1 == s.tellg());
        s.clear();
        CHECK(-1 == s.tellg());
    }

    SECTION("equal")
    {
        char act[ACT_SIZE];
        istreambuf_glue b;
        istream s(&b);

        b.pubsetbuf(dat, len);
        s.read(act, len);

        EXP_IN(s, exp, act, len);
    }

    SECTION("partial read")
    {
        char act[ACT_SIZE];
        istreambuf_glue b;
        istream s(&b);

        b.pubsetbuf(dat, len);
        s.read(act + 0, 1);
        s.read(act + 1, 2);
        s.read(act + 3, 3);
        s.read(act + 6, 4);

        EXP_IN(s, exp, act, 10);

        s.read(act + 10, len - 10);

        EXP_IN(s, exp, act, len);
    }

    SECTION("EOF")
    {
        char act[ACT_SIZE];
        istreambuf_glue b;
        istream s(&b);

        b.pubsetbuf(dat, 10);
        s.read(act, len);

        EOF_IN(s, exp, act, 10);
    }
}

TEST_CASE("input stream - two sources", "[Stream buffers]")
{
    const char* exp = "Early bird gets a corn.";
    const int len = strlen(exp);
    char dat1[] = "Early bird";
    char dat2[] = " gets a corn.";

    SECTION("equal")
    {
        char act[ACT_SIZE];
        istreambuf_glue b;
        istream s(&b);

        b.pubsetbuf(dat1, strlen(dat1))->pubsetbuf(dat2, strlen(dat2));
        s.read(act, len);

        EXP_IN(s, exp, act, len);
    }

    SECTION("partial read")
    {
        char act[ACT_SIZE];
        istreambuf_glue b;
        istream s(&b);

        b.pubsetbuf(dat1, strlen(dat1))->pubsetbuf(dat2, strlen(dat2));
        s.read(act + 0, 1);
        s.read(act + 1, 2);
        s.read(act + 3, 3);
        s.read(act + 6, 4);

        EXP_IN(s, exp, act, 10);

        s.read(act + 10, len - 10);

        EXP_IN(s, exp, act, len);
    }

    SECTION("EOF")
    {
        char act[ACT_SIZE];
        istreambuf_glue b;
        istream s(&b);

        b.pubsetbuf(dat1, strlen(dat1))->pubsetbuf(dat2, 1);
        s.read(act, len);

        EOF_IN(s, exp, act, 11);
    }
}

TEST_CASE("input stream - last chunk offset", "[Stream buffers]")
{
    SECTION("no data")
    {
        char act[ACT_SIZE];
        istreambuf_glue b;
        istream s(&b);

        CHECK(0 == b.last_chunk_offset());

        s.read(act, 1);
        CHECK(0 == b.last_chunk_offset());
    }

    SECTION("single buffer")
    {
        char dat1[] = "01234567";

        char act[ACT_SIZE];
        istreambuf_glue b;
        istream s(&b);

        CHECK(0 == b.last_chunk_offset());

        b.pubsetbuf(dat1, strlen(dat1));
        CHECK(0 == b.last_chunk_offset());

        s.read(act, 1);
        CHECK(0 == b.last_chunk_offset());
        CHECK(1 == BYTES_READ(s, b));

        s.read(act, 2);
        CHECK(0 == b.last_chunk_offset());
        CHECK(3 == BYTES_READ(s, b));

        s.read(act, 5);
        CHECK(0 == b.last_chunk_offset());
        CHECK(8 == BYTES_READ(s, b));

        s.read(act, 1);
        CHECK(0 == b.last_chunk_offset());
        CHECK(8 == BYTES_READ(s, b));
    }

    SECTION("two buffers")
    {
        char dat1[] = "0123";
        char dat2[] = "4567";

        char act[ACT_SIZE];
        istreambuf_glue b;
        istream s(&b);

        CHECK(0 == b.last_chunk_offset());

        b.pubsetbuf(dat1, strlen(dat1))->pubsetbuf(dat2, strlen(dat2));
        CHECK(4 == b.last_chunk_offset());
        CHECK(0 == BYTES_READ(s, b));

        s.read(act, 1);
        CHECK(4 == b.last_chunk_offset());
        CHECK(0 == BYTES_READ(s, b));

        s.read(act, 1);
        CHECK(4 == b.last_chunk_offset());
        CHECK(0 == BYTES_READ(s, b));

        s.read(act, 4);
        CHECK(4 == b.last_chunk_offset());
        CHECK(2 == BYTES_READ(s, b));

        s.read(act, 2);
        CHECK(4 == b.last_chunk_offset());
        CHECK(4 == BYTES_READ(s, b));

        s.read(act, 1);
        CHECK(4 == b.last_chunk_offset());
        CHECK(4 == BYTES_READ(s, b));
    }

    SECTION("three buffers")
    {
        char dat1[] = "0123";
        char dat2[] = "4567";
        char dat3[] = "89+*";

        char act[ACT_SIZE];
        istreambuf_glue b;
        istream s(&b);

        CHECK(0 == b.last_chunk_offset());

        b.pubsetbuf(dat1, strlen(dat1))->pubsetbuf(dat2, strlen(dat2))->pubsetbuf(dat3, strlen(dat3));
        CHECK(8 == b.last_chunk_offset());
        CHECK(0 == BYTES_READ(s, b));

        s.read(act, 3);
        CHECK(8 == b.last_chunk_offset());
        CHECK(0 == BYTES_READ(s, b));

        s.read(act, 3);
        CHECK(8 == b.last_chunk_offset());
        CHECK(0 == BYTES_READ(s, b));

        s.read(act, 3);
        CHECK(8 == b.last_chunk_offset());
        CHECK(1 == BYTES_READ(s, b));

        s.read(act, 3);
        CHECK(8 == b.last_chunk_offset());
        CHECK(4 == BYTES_READ(s, b));

        s.read(act, 1);
        CHECK(8 == b.last_chunk_offset());
        CHECK(4 == BYTES_READ(s, b));
    }
}

TEST_CASE("output buffer - basic", "[Stream buffers]")
{
    const char exp[EXP_SIZE] = "ABC";

    SECTION("no input")
    {
        const char* n = "";
        const int l = strlen(n);

        ostreambuf_infl b;

        EXP_RES(b, n, l, 0);
    }

    SECTION("put char")
    {
        ostreambuf_infl b;

        int c = b.sputc('A');
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::out);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::out);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::out);

        CHECK((c == 'A'));
        CHECK(off_b == 0);
        CHECK(off_c == 1);
        CHECK((off_e == 2048));

        EXP_RES(b, exp, 1, 2048);
    }

    SECTION("put two chars")
    {
        ostreambuf_infl b;

        int c1 = b.sputc('A');
        int off_1 = b.pubseekoff(0, ios_base::cur, ios_base::out);
        int c2 = b.sputc('B');
        int off_2 = b.pubseekoff(0, ios_base::cur, ios_base::out);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::out);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::out);

        CHECK((c1 == 'A'));
        CHECK((c2 == 'B'));
        CHECK(off_b == 0);
        CHECK(off_1 == 1);
        CHECK((off_2 == 2));
        CHECK((off_e == 2048));

        EXP_RES(b, exp, 2, 2048);
    }

    SECTION("extend buffer")
    {
        ostreambuf_infl b;

        int c1 = b.sputc('A');
        int off_1 = b.pubseekoff(0, ios_base::cur, ios_base::out);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::out);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::out);
        int c2 = b.sputc('Z');
        int off_2 = b.pubseekoff(0, ios_base::cur, ios_base::out);
        int off_z = b.pubseekoff(0, ios_base::end, ios_base::out);

        CHECK((c1 == 'A'));
        CHECK((c2 == 'Z'));
        CHECK(off_b == 0);
        CHECK(off_1 == 1);
        CHECK((off_2 == 2049));
        CHECK((off_e == 2048));
        CHECK((off_z == 6144));
    }

    SECTION("put sequence of chars")
    {
        ostreambuf_infl b;
        const int len = sizeof(exp);

        int n = b.sputn(exp, len);
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::out);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::out);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::out);

        CHECK((n == len));
        CHECK(off_b == 0);
        CHECK((off_c == len));
        CHECK((off_e == 4096));

        EXP_RES(b, exp, len, 4096);
    }

    SECTION("continue sequence")
    {
        ostreambuf_infl b;
        const int len = sizeof(exp) - 1;

        int c1 = b.sputc('A');
        int n = b.sputn(exp, len);
        int c2 = b.sputc('Z');
        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::out);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::out);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::out);

        CHECK((n == len));
        CHECK((c1 == 'A'));
        CHECK((c2 == 'Z'));
        CHECK(off_b == 0);
        CHECK((off_c == (len + 2)));
        CHECK((off_e == (4096 + 2048)));
    }

    SECTION("get char sequence")
    {
        ostreambuf_infl b;
        const int exp_len = strlen(exp);
        b.sputn(exp, exp_len);

        int off_c = b.pubseekoff(-exp_len, ios_base::cur, ios_base::out);
        CHECK(off_c == 0);

        char* act_seq = new char[exp_len];
        CHECK(b.sgetn(act_seq, exp_len) == exp_len);
        CHECK(!memcmp(exp, act_seq, exp_len));
        delete[] act_seq;

        int new_off = b.pubseekoff(0, ios_base::cur, ios_base::out);
        CHECK((new_off == exp_len));
    }

    SECTION("get char sequence from the end")
    {
        ostreambuf_infl b;
        const int exp_len = strlen(exp);
        char* buf = new char[exp_len];
        memcpy(buf, exp, exp_len);
        b.pubsetbuf(buf, exp_len);

        int data_off = b.pubseekoff(exp_len, ios_base::beg, ios_base::out);
        CHECK((data_off == exp_len));

        char* act_seq = new char[exp_len];
        memset(act_seq, '\0', exp_len);
        CHECK(b.sgetn(act_seq, exp_len) == 0);
        CHECK(strlen(act_seq) == 0);
        delete[] act_seq;

        int new_off = b.pubseekoff(0, ios_base::cur, ios_base::out);
        CHECK((new_off == exp_len));
    }

    SECTION("get char sequence more than available")
    {
        ostreambuf_infl b;
        const int exp_len = strlen(exp);
        char* buf = new char[exp_len];
        memcpy(buf, exp, exp_len);
        b.pubsetbuf(buf, exp_len);

        char* act_seq = new char[exp_len + 1];
        CHECK(b.sgetn(act_seq, exp_len + 1) == exp_len);
        CHECK(!memcmp(exp, act_seq, exp_len));
        delete[] act_seq;

        int new_off = b.pubseekoff(0, ios_base::cur, ios_base::out);
        CHECK((new_off == exp_len));
    }
}

TEST_CASE("output buffer - buffer management", "[Stream buffers]")
{
    char dat1[] = "0123";
    char dat2[] = "4567";
    char dat3[] = "89";
    char dat4[] = "-+";
    const int dat1_len = strlen(dat1);
    const int dat2_len = strlen(dat2);
    const int dat3_len = strlen(dat3);
    const int dat4_len = strlen(dat4);

    SECTION("sync")
    {
        ostreambuf_infl b;

        char* buf = new char[dat1_len];
        memcpy(buf, dat1, dat1_len);
        b.pubsetbuf(buf, dat1_len);

        int r = b.pubsync();
        CHECK((r == -1));
    }

    SECTION("changing buffer")
    {
        ostreambuf_infl b;
        const int s1 = 128;
        const int s2 = 256;
        const int s3 = 32;
        const int s4 = 64;

        b.pubsetbuf(new char[s1], s1);
        b.sputn(dat1, dat1_len);
        EXP_RES(b, dat1, dat1_len, dat1_len);

        b.pubsetbuf(new char[s2], s2);
        b.sputn(dat2, dat2_len);
        EXP_RES(b, dat2, dat2_len, dat2_len);

        b.pubsetbuf(new char[s3], s3);
        b.sputn(dat3, dat3_len);
        EXP_RES(b, dat3, dat3_len, dat3_len);

        b.pubsetbuf(new char[s4], s4);
        b.sputn(dat4, dat4_len);
        EXP_RES(b, dat4, dat4_len, dat4_len);
    }
}

TEST_CASE("output buffer - positioning", "[Stream buffers]")
{
    const char* exp = "Early bird gets a corn.";
    const int len = strlen(exp);
    const int len1d3 = strlen(exp) * 1 / 3;
    const int len2d3 = len - len1d3;

    SECTION("no data")
    {
        ostreambuf_infl b;

        int pos_c = b.pubseekpos(len / 2, ios_base::out);
        int pos_b = b.pubseekpos(0,       ios_base::out);
        int pos_e = b.pubseekpos(len,     ios_base::out);

        CHECK(pos_b == 0);
        CHECK(pos_c == 0);
        CHECK(pos_e == 0);
    }

    SECTION("wrong buffer")
    {
        ostreambuf_infl b;

        b.pubsetbuf(new char[len], len);

        int pos_c = b.pubseekpos(len / 2, ios_base::in);
        int pos_b = b.pubseekpos(0,       ios_base::in);
        int pos_e = b.pubseekpos(len,     ios_base::in);

        CHECK((pos_b == -1));
        CHECK((pos_c == -1));
        CHECK((pos_e == -1));
    }

    SECTION("out of range")
    {
        ostreambuf_infl b;
        int pos;

        b.pubsetbuf(new char[len], len);
        b.sputn(exp, len);

        pos = b.pubseekpos(0 - len, ios_base::out);
        CHECK(pos == 0);
        EXP_RES(b, exp, 0, 0);

        b.pubsetbuf(new char[len], len);
        b.sputn(exp, len);

        pos = b.pubseekpos(len + len, ios_base::out);
        CHECK((pos == len));
        EXP_RES(b, exp, len, len);
    }

    SECTION("on the edge")
    {
        ostreambuf_infl b;
        int pos;

        b.pubsetbuf(new char[len], len);
        b.sputn(exp, len);

        pos = b.pubseekpos(0 - 1, ios_base::out);
        CHECK(pos == 0);
        pos = b.pubseekpos(0 + 1, ios_base::out);
        CHECK(pos == 1);
        pos = b.pubseekpos(len, ios_base::out);
        CHECK((pos == len));
        pos = b.pubseekpos(len - 1, ios_base::out);
        CHECK((pos == (len - 1)));
        pos = b.pubseekpos(len + 1, ios_base::out);
        CHECK((pos == len));

        pos = b.pubseekpos(0, ios_base::out);
        CHECK(pos == 0);
        EXP_RES(b, exp, 0, 0);
    }

    SECTION("in range")
    {
        ostreambuf_infl b;
        int pos;

        b.pubsetbuf(new char[len], len);
        b.sputn(exp, len);

        pos = b.pubseekpos(len1d3, ios_base::out);
        CHECK((pos == len1d3));
        pos = b.pubseekpos(len2d3, ios_base::out);
        CHECK((pos == len2d3));
    }
}

TEST_CASE("output buffer - offset", "[Stream buffers]")
{
    const char* exp = "Early bird gets a corn.";
    const int len = strlen(exp);
    const int len1d3 = strlen(exp) * 1 / 3;
    const int len2d3 = len - len1d3;

    SECTION("no data")
    {
        ostreambuf_infl b;

        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::out);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::out);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::out);

        CHECK(off_b == 0);
        CHECK(off_c == 0);
        CHECK(off_e == 0);
    }

    SECTION("wrong buffer")
    {
        ostreambuf_infl b;

        b.pubsetbuf(new char[len], len);

        int off_c = b.pubseekoff(0, ios_base::cur, ios_base::in);
        int off_b = b.pubseekoff(0, ios_base::beg, ios_base::in);
        int off_e = b.pubseekoff(0, ios_base::end, ios_base::in);
        int off_a = b.pubseekoff(0, static_cast<std::ios_base::seekdir>(0x5a5a), ios_base::out);

        CHECK((off_b == -1));
        CHECK((off_c == -1));
        CHECK((off_e == -1));
        CHECK((off_a == -1));
    }

    SECTION("begin")
    {
        ostreambuf_infl b;
        int off;

        b.pubsetbuf(new char[len], len);
        b.sputn(exp, len);

        off = b.pubseekoff(0 - len - len, ios_base::beg, ios_base::out);
        CHECK(off == 0);

        off = b.pubseekoff(0 + len + len, ios_base::beg, ios_base::out);
        CHECK((off == len));

        off = b.pubseekoff(0 - 1, ios_base::beg, ios_base::out);
        CHECK(off == 0);

        off = b.pubseekoff(0 + 1, ios_base::beg, ios_base::out);
        CHECK(off == 1);

        off = b.pubseekoff(0 + len1d3, ios_base::beg, ios_base::out);
        CHECK((off == len1d3));

        off = b.pubseekoff(0 + len2d3, ios_base::beg, ios_base::out);
        CHECK((off == len2d3));

        off = b.pubseekoff(0 + len - 1, ios_base::beg, ios_base::out);
        CHECK((off == (len - 1)));

        off = b.pubseekoff(0 + len, ios_base::beg, ios_base::out);
        CHECK((off == len));

        off = b.pubseekoff(0, ios_base::beg, ios_base::out);
        CHECK(off == 0);
        EXP_RES(b, exp, 0, 0);
        b.sputn(exp, len);
        EXP_RES(b, exp, len, len);
    }

    SECTION("end")
    {
        const char* exp_alt = "Early bird gets a corn!";

        ostreambuf_infl b;
        int off;

        b.pubsetbuf(new char[len], len);
        b.sputn(exp, len);

        off = b.pubseekoff(0 - len - len, ios_base::end, ios_base::out);
        CHECK(off == 0);

        off = b.pubseekoff(0 + len + len, ios_base::end, ios_base::out);
        CHECK((off == len));

        off = b.pubseekoff(0, ios_base::end, ios_base::out);
        CHECK((off == len));

        off = b.pubseekoff(0 - 1, ios_base::end, ios_base::out);
        CHECK((off == (len - 1)));

        off = b.pubseekoff(0 + 1, ios_base::end, ios_base::out);
        CHECK((off == len));

        off = b.pubseekoff(0 - len1d3, ios_base::end, ios_base::out);
        CHECK((off == len2d3));

        off = b.pubseekoff(0 - len2d3, ios_base::end, ios_base::out);
        CHECK((off == len1d3));

        off = b.pubseekoff(0 - len + 1, ios_base::end, ios_base::out);
        CHECK(off == 1);

        off = b.pubseekoff(0 - len, ios_base::end, ios_base::out);
        CHECK(off == 0);

        b.pubsetbuf(new char[len], len);
        b.sputn(exp, len);
        off = b.pubseekoff(- 1, ios_base::end, ios_base::out);
        CHECK((off == (len - 1)));
        b.sputn("!", 1);
        off = b.pubseekoff(0, ios_base::end, ios_base::out);
        CHECK((off == len));
        EXP_RES(b, exp_alt, len, len);
    }

    SECTION("current")
    {
        const char* exp_alt = "Early birds get a worm.";
        const char* ovr_alt = "s get a worm.";
        int off_alt = strlen(ovr_alt);

        ostreambuf_infl b;
        int off;

        b.pubsetbuf(new char[len], len);
        b.sputn(exp, len);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::out);
        off = b.pubseekoff(0 - len - len, ios_base::cur, ios_base::out);
        CHECK(off == 0);

        b.pubseekoff(len1d3, ios_base::beg, ios_base::out);
        off = b.pubseekoff(0 + len + len, ios_base::cur, ios_base::out);
        CHECK((off == len));

        b.pubseekoff(len1d3, ios_base::beg, ios_base::out);
        off = b.pubseekoff(0, ios_base::cur, ios_base::out);
        CHECK((off == len1d3));

        b.pubseekoff(len1d3, ios_base::beg, ios_base::out);
        off = b.pubseekoff(0 - 1, ios_base::cur, ios_base::out);
        CHECK((off == (len1d3 - 1)));

        b.pubseekoff(len1d3, ios_base::beg, ios_base::out);
        off = b.pubseekoff(0 + 1, ios_base::cur, ios_base::out);
        CHECK((off == (len1d3 + 1)));

        b.pubseekoff(len1d3, ios_base::beg, ios_base::out);
        off = b.pubseekoff(0 + len1d3, ios_base::cur, ios_base::out);
        CHECK((off == (len1d3 + len1d3)));

        b.pubseekoff(len1d3, ios_base::beg, ios_base::out);
        off = b.pubseekoff(0 + len2d3, ios_base::cur, ios_base::out);
        CHECK((off == len));

        b.pubseekoff(len1d3, ios_base::beg, ios_base::out);
        off = b.pubseekoff(0 + len, ios_base::cur, ios_base::out);
        CHECK((off == len));

        b.pubsetbuf(new char[len], len);
        b.sputn(exp, len);
        b.pubseekoff(- off_alt, ios_base::end, ios_base::out);
        off = b.pubseekoff(0, ios_base::cur, ios_base::out);
        CHECK(off == len - off_alt);
        b.sputn(ovr_alt, off_alt);
        off = b.pubseekoff(0, ios_base::end, ios_base::out);
        CHECK((off == len));
        EXP_RES(b, exp_alt, len, len);
    }
}

TEST_CASE("output stream - basic", "[Stream buffers]")
{
    SECTION("no input")
    {
        const char* exp = "";
        const int exp_len = strlen(exp);

        ostreambuf_infl b;
        ostream s(&b);

        EXP_OUT(s, exp, exp_len);
    }

    SECTION("1 byte input")
    {
        const char* src = "A";
        const int src_len = strlen(src);
        const char* exp = "A";
        const int exp_len = strlen(exp);

        ostreambuf_infl b;
        ostream s(&b);

        s.write(src, src_len);

        EXP_OUT(s, exp, exp_len);
    }

    SECTION("8 bytes input")
    {
        const char* src = "12345678";
        const int src_len = strlen(src);
        const char* exp = "12345678";
        const int exp_len = strlen(exp);

        ostreambuf_infl b;
        ostream s(&b);

        s.write(src, src_len);

        EXP_OUT(s, exp, exp_len);
    }

    SECTION("partial write")
    {
        const char* src = "12345678";
        const int src_len = strlen(src);
        const char* exp = "12345678";
        const int exp_len = strlen(exp);

        ostreambuf_infl b;
        ostream s(&b);

        for (const char* c = src; c < src + src_len; ++c)
            s.write(c, 1);

        EXP_OUT(s, exp, exp_len);
    }
}

TEST_CASE("output stream - reserved size", "[Stream buffers]")
{
    SECTION("no input")
    {
        const char* exp = "";
        const int exp_len = strlen(exp);

        ostreambuf_infl b;
        ostream s(&b);

        b.reserve(32);

        EXP_OUT(s, exp, exp_len);
    }

    SECTION("1 byte input")
    {
        const char* src = "A";
        const int src_len = strlen(src);
        const char* exp = "A";
        const int exp_len = strlen(exp);

        ostreambuf_infl b;
        ostream s(&b);

        b.reserve(32);
        s.write(src, src_len);

        EXP_OUT(s, exp, exp_len);
    }

    SECTION("8 bytes input")
    {
        const char* src = "12345678";
        const int src_len = strlen(src);
        const char* exp = "12345678";
        const int exp_len = strlen(exp);

        ostreambuf_infl b;
        ostream s(&b);

        b.reserve(32);
        s.write(src, src_len);

        EXP_OUT(s, exp, exp_len);
    }

    SECTION("partial write")
    {
        const char* src = "12345678";
        const int src_len = strlen(src);
        const char* exp = "12345678";
        const int exp_len = strlen(exp);

        ostreambuf_infl b;
        ostream s(&b);

        b.reserve(32);
        for (const char* c = src; c < src + src_len; ++c)
            s.write(c, 1);

        EXP_OUT(s, exp, exp_len);
    }
}

TEST_CASE("output stream - large data", "[Stream buffers]")
{
    const int len = 1 << 21;
    const int plen = 1 << 12;
    vector<char> chars(len, '\0');
    generate_n(chars.begin(), len, rand);

    SECTION("0 bytes reserved")
    {
        const char* src = chars.data();
        const char* exp = chars.data();

        ostreambuf_infl b;
        ostream s(&b);

        for (int i = 0; i < len; i += plen, src += plen)
            s.write(src, plen);

        EOF_OUT(s, exp, 1 << 20);
    }

    SECTION("2^10 bytes reserved")
    {
        const char* src = chars.data();
        const char* exp = chars.data();

        ostreambuf_infl b;
        ostream s(&b);

        b.reserve(1 << 10);
        for (int i = 0; i < len; i += plen, src += plen)
            s.write(src, plen);

        EOF_OUT(s, exp, 1 << 20);
    }

    SECTION("2^18 bytes reserved")
    {
        const char* src = chars.data();
        const char* exp = chars.data();

        ostreambuf_infl b;
        ostream s(&b);

        b.reserve(1 << 18);
        for (int i = 0; i < len; i += plen, src += plen)
            s.write(src, plen);

        EOF_OUT(s, exp, 1 << 20);
    }
}
