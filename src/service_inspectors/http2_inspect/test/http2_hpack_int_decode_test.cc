//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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

// http2_hpack_int_decode_test.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../http2_enum.h"

using namespace Http2Enums;
#include "../http2_hpack_int_decode.h"
#include "../http2_varlen_int_decode_impl.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

namespace snort
{
// Stubs whose sole purpose is to make the test code link
int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
}


//
// The following tests should result in a successful decode, no infractions/events
//
TEST_GROUP(http2_hpack_int_decode_success)
{
    Http2EventGen events;
    Http2Infractions inf;
    Http2HpackIntDecode* const decode = new Http2HpackIntDecode(5);

    void teardown() override
    {
        CHECK(inf.none_found() == true);
        delete decode;
    }
};

TEST(http2_hpack_int_decode_success, 10_using_5_bits)
{
    // prepare buf to decode - example from RFC 7541 c.1.1
    uint8_t buf = 10;
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = decode->translate(&buf, 1, bytes_processed, res, &events, &inf, false);
    // check results
    CHECK(success == true);
    CHECK(res == 10);
    CHECK(bytes_processed == 1);
}

TEST(http2_hpack_int_decode_success, 10_using_5_bits_wtail)
{
    // prepare buf to decode - same as above with an extra byte as leftover
    uint8_t buf[2] = { 10, 0xff };
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = decode->translate(buf, 2, bytes_processed, res, &events, &inf, false);
    // check results
    CHECK(success == true);
    CHECK(res == 10);
    CHECK(bytes_processed == 1);
}

TEST(http2_hpack_int_decode_success, 1337_using_5_bits)
{
    // prepare buf to decode - example from RFC 7541 c.1.2
    uint8_t buf[3] = { 31, 0x9a, 10 };
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = decode->translate(buf, 3, bytes_processed, res, &events, &inf, false);
    // check results
    CHECK(success == true);
    CHECK(res == 1337);
    CHECK(bytes_processed == 3);
}

TEST(http2_hpack_int_decode_success, 42_using_8_bits)
{
    // prepare decode object
    Http2HpackIntDecode decode_8(8);
    // prepare buf to decode - example from RFC 7541 c.1.3
    uint8_t buf = 42;
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = decode_8.translate(&buf, 1, bytes_processed, res, &events, &inf, false);
    // check results
    CHECK(success == true);
    CHECK(res == 42);
    CHECK(bytes_processed == 1);
}

TEST(http2_hpack_int_decode_success, max_val_using_5_bit)
{
    // prepare buf to decode - 2^64-1
    uint8_t buf[11] = { 31, 0xE0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 1 };
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = decode->translate(buf, 11, bytes_processed, res, &events, &inf, false);
    // check results
    CHECK(success == true);
    CHECK(res == 0xFFFFFFFFFFFFFFFF);
    CHECK(bytes_processed == 11);
}

TEST(http2_hpack_int_decode_success, 31_using_5_bits)
{
    // prepare buf to decode - 2^N -1
    uint8_t buf[2] = { 31, 0 };
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = decode->translate(buf, 2, bytes_processed, res, &events, &inf, false);
    // check results
    CHECK(success == true);
    CHECK(res == 31);
    CHECK(bytes_processed == 2);
}

TEST(http2_hpack_int_decode_success, 0_using_5_bits)
{
    // prepare buf to decode - 0 using 5 bits
    uint8_t buf = 0;
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = decode->translate(&buf, 1, bytes_processed, res, &events, &inf, false);
    // check results
    CHECK(success == true);
    CHECK(res == 0);
    CHECK(bytes_processed == 1);
}

TEST(http2_hpack_int_decode_success, MAX_UINT32_using_7_bits)
{
    // prepare decode object
    Http2HpackIntDecode decode_7(7);
    // prepare buf to decode - MAX_UINT32 using 7 bits
    uint8_t buf[6] = {0x7f, 0x80, 0xff, 0xff, 0xff, 0xf};
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = decode_7.translate(buf, 6, bytes_processed, res, &events, &inf, false);
    // check results
    CHECK(success == true);
    CHECK(res == UINT32_MAX);
    CHECK(bytes_processed == 6);
}

//
// The following tests should result in a failure and set infractions/events
//
TEST_GROUP(http2_hpack_int_decode_failure)
{
};

TEST(http2_hpack_int_decode_failure, 0_len_field)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackIntDecode decode_8(8);
    // prepare buf to decode - use buf length 0
    uint8_t buf = 42;
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = decode_8.translate(&buf, 0, bytes_processed, res, &local_events, &local_inf,
        false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 0);
    CHECK(local_inf.get_raw(0) == (1<<INF_INT_EMPTY_BUFF));
}

TEST(http2_hpack_int_decode_failure, too_short)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackIntDecode local_decode(5);
    // prepare buf to decode - buffer ends before decode finished
    uint8_t buf[3] = { 31, 0x9a, 10 };
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = local_decode.translate(buf, 2, bytes_processed, res, &local_events, &local_inf,
        false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 2);
    CHECK(local_inf.get_raw(0) == (1<<INF_INT_MISSING_BYTES));
}

TEST(http2_hpack_int_decode_failure, multiplier_bigger_than_63)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackIntDecode local_decode(5);
    // prepare buf to decode - multiplier > 63
    uint8_t buf[13] = { 31, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x81, 1 };
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = local_decode.translate(buf, 13, bytes_processed, res, &local_events, &local_inf,
        false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 11);
    CHECK(local_inf.get_raw(0) == (1<<INF_INT_OVERFLOW));
}

TEST(http2_hpack_int_decode_failure, add_val_overflow)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackIntDecode local_decode(5);
    // prepare buf to decode - value to add itself is already creating overflow
    uint8_t buf[12] = { 31, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xFF, 1 };
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = local_decode.translate(buf, 12, bytes_processed, res, &local_events, &local_inf,
        false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 11);
    CHECK(local_inf.get_raw(0) == (1<<INF_INT_OVERFLOW));
}

TEST(http2_hpack_int_decode_failure, add_val_overflow2)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackIntDecode local_decode(5);
    // prepare buf to decode - adding value to result kept so far creates overflow
    uint8_t buf[11] = { 31, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 1 };
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = local_decode.translate(buf, 11, bytes_processed, res, &local_events, &local_inf,
        false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 11);
    CHECK(local_inf.get_raw(0) == (1<<INF_INT_OVERFLOW));
}

TEST(http2_hpack_int_decode_failure, 2_64_using_5_bit)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackIntDecode local_decode(5);
    // prepare buf to decode - 2^64
    uint8_t buf[11] = { 31, 0xE1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 1 };
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = local_decode.translate(buf, 11, bytes_processed, res, &local_events, &local_inf,
        false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 11);
    CHECK(local_inf.get_raw(0) == (1<<INF_INT_OVERFLOW));
}

//
// The following tests should result in a successful decode and set
// leading zeros infraction and event
//
TEST_GROUP(http2_hpack_int_decode_leading_zeros)
{
};

TEST(http2_hpack_int_decode_leading_zeros, leading_zeros)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackIntDecode local_decode(5);
    // prepare buf to decode - MSB is zero
    uint8_t buf[3] = { 31, 0x80, 0 };
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = local_decode.translate(buf, 3, bytes_processed, res, &local_events, &local_inf,
        false);
    // check results
    CHECK(success == true);
    CHECK(res == 31);
    CHECK(bytes_processed == 3);
    CHECK(local_inf.get_raw(0) == (1<<INF_INT_LEADING_ZEROS));
}

TEST(http2_hpack_int_decode_leading_zeros, leading_0_byte_11)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackIntDecode local_decode(5);
    // prepare buf to decode - multiplier 63 doesn't create overflow, should alert on
    // leading 0
    uint8_t buf[11] = { 31, 0xE0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0 };
    // decode
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    bool success = local_decode.translate(buf, 11, bytes_processed, res, &local_events, &local_inf,
        false);
    // check results
    CHECK(success == true);
    CHECK(res == 0x7FFFFFFFFFFFFFFF);
    CHECK(bytes_processed == 11);
    CHECK(local_inf.get_raw(0) == (1<<INF_INT_LEADING_ZEROS));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

