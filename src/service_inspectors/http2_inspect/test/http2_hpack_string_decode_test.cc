//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

// http2_hpack_string_decode_test.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../http2_enum.h"
#include "../http2_hpack_string_decode.h"
#include "../../http_inspect/http_enum.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

namespace snort
{
// Stubs whose sole purpose is to make the test code link
int DetectionEngine::queue_event(unsigned int, unsigned int, Actions::Type) { return 0; }
}

using namespace Http2Enums;

//
// The following tests should result in a successful decode, no infractions/events
//
TEST_GROUP(http2_hpack_string_decode_success)
{
    Http2EventGen events;
    Http2Infractions inf;
    Http2HpackStringDecode* const decode = new Http2HpackStringDecode(&events, &inf);

    void teardown() override
    {
        CHECK(inf.none_found() == true);
        CHECK(events.none_found() == true);
        delete decode;
    }
};

TEST(http2_hpack_string_decode_success, custom_key_len_10)
{
    // prepare buf to decode - example from RFC 7541 c.3.3
    uint8_t buf[11] = { 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79 };
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[10];
    bool success = decode->translate(buf, 11, bytes_processed, res, 10, bytes_written);
    // check results
    CHECK(success == true);
    CHECK(memcmp(res, "custom-key", 10) == 0);
    CHECK(bytes_processed == 11);
    CHECK(bytes_written == 10);
}

TEST(http2_hpack_string_decode_success, custom_key_len_10_wtail)
{
    // prepare buf to decode - same as above with an extra byte as leftover
    uint8_t buf[12] = { 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x79 };
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[12];
    bool success = decode->translate(buf, 12, bytes_processed, res, 12, bytes_written);
    // check results
    CHECK(success == true);
    CHECK(memcmp(res, "custom-key", 10) == 0);
    CHECK(bytes_processed == 11);
    CHECK(bytes_written == 10);
}

TEST(http2_hpack_string_decode_success, int_is_more_than_1_byte)
{
    // prepare buf to decode - length is 2^7
    uint8_t buf[130];
    buf[0] = 0x7f;
    buf[1] = 1;
    memset(&buf[2], 'A', 128);
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[130];
    bool success = decode->translate(buf, 130, bytes_processed, res, 130, bytes_written);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 130);
    CHECK(bytes_written == 128);
    CHECK(memcmp(res, &buf[2], 128) == 0);
}

TEST(http2_hpack_string_decode_success, empty_string)
{
    // prepare buf to decode - length is 0 (empty string)
    uint8_t buf = 0;
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res = 10; // random value, just to check it wasn't overwritten
    bool success = decode->translate(&buf, 1, bytes_processed, &res, 1, bytes_written);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 1);
    CHECK(bytes_written == 0);
    CHECK(res == 10);
}

TEST(http2_hpack_string_decode_success, string_len_1)
{
    // prepare buf to decode - length is 1
    uint8_t buf[2] = { 1, 'A' };
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res = 0;
    bool success = decode->translate(buf, 2, bytes_processed, &res, 1, bytes_written);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 2);
    CHECK(bytes_written == 1);
    CHECK(res == 'A');
}

TEST(http2_hpack_string_decode_success, max_field_length)
{
    // prepare buf to decode - int + string == MAX_OCTETS (Field limitation)
    uint8_t buf[HttpEnums::MAX_OCTETS];
    buf[0] = 0x7F;
    buf[1] = 0xA1;
    buf[2] = 0xF1;
    buf[3]= 0x3;
    memset(&buf[4], 'A', HttpEnums::MAX_OCTETS-4);
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[HttpEnums::MAX_OCTETS];
    bool success = decode->translate(buf, HttpEnums::MAX_OCTETS, bytes_processed, res,
        HttpEnums::MAX_OCTETS, bytes_written);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == HttpEnums::MAX_OCTETS);
    CHECK(bytes_written == (HttpEnums::MAX_OCTETS-4));
    CHECK(memcmp(res, &buf[4], bytes_written) == 0);
}

//
// The following tests should trigger infractions/events
//
TEST_GROUP(http2_hpack_string_decode_infractions)
{
};

TEST(http2_hpack_string_decode_infractions, 0_len_field)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode(&local_events, &local_inf);
    // prepare buf to decode - use field length 0
    uint8_t buf = 0;
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res;
    bool success = local_decode.translate(&buf, 0, bytes_processed, &res, 1, bytes_written);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 0);
    CHECK(bytes_written == 0);
    CHECK(local_inf.get_raw() == (1<<INF_STRING_EMPTY_BUFF));
    CHECK(local_events.get_raw() == (1<<(EVENT_STRING_DECODE_FAILURE-1)));
}

TEST(http2_hpack_string_decode_infractions, missing_bytes)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode(&local_events, &local_inf);
    // prepare buf to decode - length is 1, no string
    uint8_t buf = 1;
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[2];
    bool success = local_decode.translate(&buf, 1, bytes_processed, res, 2, bytes_written);
    // check results
    CHECK(success == false);
    CHECK(bytes_written == 0);
    CHECK(bytes_processed == 1);
    CHECK(local_inf.get_raw() == (1<<INF_STRING_MISSING_BYTES));
    CHECK(local_events.get_raw() == (1<<(EVENT_STRING_DECODE_FAILURE-1)));
}

TEST(http2_hpack_string_decode_infractions, bad_int)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode(&local_events, &local_inf);
    // prepare buf to decode - bad int
    uint8_t buf[2] = { 0x7f, 0x80 };
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[2];
    bool success = local_decode.translate(buf, 2, bytes_processed, res, 2, bytes_written);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 2);
    CHECK(bytes_written == 0);
    CHECK(local_inf.get_raw() == (1<<INF_INT_MISSING_BYTES));
    CHECK(local_events.get_raw() == (1<<(EVENT_INT_DECODE_FAILURE-1)));
}

TEST(http2_hpack_string_decode_infractions, max_field_length_plus_1)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode(&local_events, &local_inf);
    // prepare buf to decode -  int + string == MAX_OCTETS+1 (Field limitation + 1)
    uint8_t buf[HttpEnums::MAX_OCTETS];
    buf[0] = 0x7F;
    buf[1] = 0xA2;
    buf[2] = 0xF1;
    buf[3]= 0x3;
    memset(&buf[4], 'A', HttpEnums::MAX_OCTETS-4);
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[HttpEnums::MAX_OCTETS];
    bool success = local_decode.translate(buf, HttpEnums::MAX_OCTETS, bytes_processed, res,
        HttpEnums::MAX_OCTETS, bytes_written);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 4);
    CHECK(bytes_written == 0);
    CHECK(local_inf.get_raw() == (1<<INF_STRING_MISSING_BYTES));
    CHECK(local_events.get_raw() == (1<<(EVENT_STRING_DECODE_FAILURE-1)));
}

TEST(http2_hpack_string_decode_infractions, out_buf_out_of_space)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode(&local_events, &local_inf);
    // prepare buf to decode 
    uint8_t buf[HttpEnums::MAX_OCTETS];
    buf[0] = 0x7F;
    buf[1] = 0xA1;
    buf[2] = 0xF1;
    buf[3]= 0x3;
    memset(&buf[4], 'A', HttpEnums::MAX_OCTETS-4);
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[HttpEnums::MAX_OCTETS-5];
    bool success = local_decode.translate(buf, HttpEnums::MAX_OCTETS, bytes_processed, res,
        HttpEnums::MAX_OCTETS-5, bytes_written);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 4);
    CHECK(bytes_written == 0);
    CHECK(local_inf.get_raw() == (1<<INF_OUT_BUFF_OUT_OF_SPACE));
    CHECK(local_events.get_raw() == (1<<(EVENT_STRING_DECODE_FAILURE-1)));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

