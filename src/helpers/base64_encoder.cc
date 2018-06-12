//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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

// base64_encoder.cc author Russ Combs <rucombs@cisco.com>

// this is based on the excellent work by devolve found at
// https://sourceforge.net/projects/libb64/.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "base64_encoder.h"

#include <cassert>

#ifdef UNIT_TEST
#include <cstring>
#include "catch/snort_catch.h"
#endif

using namespace snort;

static inline char b64(uint8_t idx)
{
    static const char* encoding =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    assert(idx < 64);
    return encoding[idx];
}

unsigned Base64Encoder::encode(
    const uint8_t* plain_text, unsigned length, char* buf)
{
    const uint8_t* data = plain_text;
    const uint8_t* const data_end = plain_text + length;
    char* p = buf;

    switch (step)
    {
        while (true)
        {
            uint8_t fragment;
    case step_A:
            if (data == data_end)
            {
                step = step_A;
                return p - buf;
            }
            fragment = *data++;
            state = (fragment & 0x0fc) >> 2;
            *p++ = b64(state);
            state = (fragment & 0x003) << 4;
            // fallthrough
    case step_B:
            if (data == data_end)
            {
                step = step_B;
                return p - buf;
            }
            fragment = *data++;
            state |= (fragment & 0x0f0) >> 4;
            *p++ = b64(state);
            state = (fragment & 0x00f) << 2;
            // fallthrough
    case step_C:
            if (data == data_end)
            {
                step = step_C;
                return p - buf;
            }
            fragment = *data++;
            state |= (fragment & 0x0c0) >> 6;
            *p++ = b64(state);
            state  = (fragment & 0x03f) >> 0;
            *p++ = b64(state);
        }
    }
    /* control should not reach here */
    assert(false);
    return p - buf;
}

unsigned Base64Encoder::finish(char* buf)
{
    char* p = buf;

    switch (step)
    {
    case step_B:
        *p++ = b64(state);
        *p++ = '=';
        *p++ = '=';
        break;
    case step_C:
        *p++ = b64(state);
        *p++ = '=';
        break;
    case step_A:
        break;
    }
    return p - buf;
}

//--------------------------------------------------------------------------
// unit tests
// code string generated with: echo <text> | base64 -
// which adds a \n to the input.
//--------------------------------------------------------------------------

#ifdef UNIT_TEST
TEST_CASE("b64 decode", "[Base64Encoder]")
{
    Base64Encoder b64;

    const char* text = "The quick brown segment jumped over the lazy dogs.\n";
    const char* code = "VGhlIHF1aWNrIGJyb3duIHNlZ21lbnQganVtcGVkIG92ZXIgdGhlIGxhenkgZG9ncy4K";

    char buf[256];

    SECTION("no decode")
    {
        CHECK(!b64.finish(buf));
    }
    SECTION("null data")
    {
        CHECK(!b64.encode(nullptr, 0, buf));
        CHECK(!b64.finish(buf));
    }
    SECTION("zero length data")
    {
        CHECK(!b64.encode((const uint8_t*)"ignore", 0, buf));
        CHECK(!b64.finish(buf));
    }
    SECTION("finish states")
    {
        const char* txt[] = { "test0\n",  "test01\n",     "test012\n" };
        const char* exp[] = { "dGVzdDAK", "dGVzdDAxCg==", "dGVzdDAxMgo=" };

        const unsigned to_do = sizeof(txt)/sizeof(txt[0]);

        for ( unsigned i = 0; i < to_do; ++i )
        {
            unsigned n = b64.encode((const uint8_t*)txt[i], strlen(txt[i]), buf);
            n += b64.finish(buf+n);

            REQUIRE(n < sizeof(buf));
            buf[n] = 0;

            CHECK(!strcmp(buf, exp[i]));
            b64.reset();
        }
    }
    SECTION("one shot")
    {
        unsigned n = b64.encode((const uint8_t*)text, strlen(text), buf);
        n += b64.finish(buf+n);

        REQUIRE(n < sizeof(buf));
        buf[n] = 0;

        CHECK(!strcmp(buf, code));
    }
    SECTION("slice and dice")
    {
        unsigned len = strlen(text);

        for ( unsigned chunk = 1; chunk < len; ++chunk )
        {
            memset(buf, 0, sizeof(buf));
            unsigned offset = 0;
            unsigned n = 0;

            while ( offset < len )
            {
                unsigned k = (offset + chunk > len) ? len - offset : chunk;
                n += b64.encode((const uint8_t*)text+offset, k, buf+n);
                offset += k;
            }
            n += b64.finish(buf+n);

            REQUIRE(n < sizeof(buf));
            buf[n] = 0;

            CHECK(!strcmp(buf, code));
            b64.reset();
        }
    }
}
#endif

