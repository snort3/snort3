//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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
#include "../http2_huffman_state_machine.h"

#include "../http2_hpack_int_decode.h"
#include "../http2_hpack_string_decode.h"
using namespace Http2Enums;
#include "../http2_varlen_int_decode_impl.h"
#include "../http2_varlen_string_decode_impl.h"
#include "../../http_inspect/http_common.h"
#include "../../http_inspect/http_enum.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

namespace snort
{
// Stubs whose sole purpose is to make the test code link
int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
}

using namespace HttpCommon;

//
// The following tests should result in a successful decode, no infractions/events
//
TEST_GROUP(http2_hpack_string_decode_success)
{
    Http2EventGen events;
    Http2Infractions inf;
    Http2HpackStringDecode* const decode = new Http2HpackStringDecode();
    Http2HpackIntDecode decode_int7{7}; // cppcheck-suppress unreadVariable

    void teardown() override
    {
        CHECK(inf.none_found() == true);
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
    bool success = decode->translate(buf, 11, decode_int7, bytes_processed, res, 10, bytes_written, &events,
        &inf, false);
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
    bool success = decode->translate(buf, 12, decode_int7, bytes_processed, res, 12, bytes_written, &events,
        &inf, false);
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
    bool success = decode->translate(buf, 130, decode_int7, bytes_processed, res, 130, bytes_written, &events,
        &inf, false);
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
    bool success = decode->translate(&buf, 1, decode_int7, bytes_processed, &res, 1, bytes_written, &events,
        &inf, false);
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
    bool success = decode->translate(buf, 2, decode_int7, bytes_processed, &res, 1, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 2);
    CHECK(bytes_written == 1);
    CHECK(res == 'A');
}

TEST(http2_hpack_string_decode_success, max_field_length)
{
    // prepare buf to decode - int + string == MAX_OCTETS (Field limitation)
    uint8_t buf[MAX_OCTETS];
    buf[0] = 0x7F;
    buf[1] = 0xA1;
    buf[2] = 0xF1;
    buf[3]= 0x3;
    memset(&buf[4], 'A', MAX_OCTETS-4);
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[MAX_OCTETS];
    bool success = decode->translate(buf, MAX_OCTETS, decode_int7, bytes_processed, res,
        MAX_OCTETS, bytes_written, &events, &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == MAX_OCTETS);
    CHECK(bytes_written == (MAX_OCTETS-4));
    CHECK(memcmp(res, &buf[4], bytes_written) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_1_byte)
{
    // prepare buf to decode - Huffman '%'
    uint8_t buf[2] = {0x81, 0x57};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[1];
    bool success = decode->translate(buf, 2, decode_int7, bytes_processed, res, 1, bytes_written, &events, &inf,
        false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 2);
    CHECK(bytes_written == 1);
    CHECK(res[0] == '%');
}

TEST(http2_hpack_string_decode_success, huffman_1_byte_star)
{
    // prepare buf to decode - Huffman '*'
    uint8_t buf[2] = {0x81, 0xf9};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[1];
    bool success = decode->translate(buf, 2, decode_int7, bytes_processed, res, 1, bytes_written, &events, &inf,
        false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 2);
    CHECK(bytes_written == 1);
    CHECK(res[0] == '*');
}

TEST(http2_hpack_string_decode_success, huffman_2_bytes_aligned)
{
    // prepare buf to decode - Huffman "&&"
    uint8_t buf[3] = {0x82, 0xf8, 0xf8};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[3];
    bool success = decode->translate(buf, 3, decode_int7, bytes_processed, res, 3, bytes_written, &events, &inf,
        false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 3);
    CHECK(bytes_written == 2);
    CHECK(memcmp(res, "&&", 2) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_2_bytes_unaligned)
{
    // prepare buf to decode - Huffman "%%"
    uint8_t buf[3] = {0x82, 0x55, 0x5f};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[3];
    bool success = decode->translate(buf, 3, decode_int7, bytes_processed, res, 3, bytes_written, &events, &inf,
        false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 3);
    CHECK(bytes_written == 2);
    CHECK(memcmp(res, "%%", 2) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_rfc_example1)
{
    // prepare buf to decode - Huffman "www.example.com" , RFC c.4.1
    uint8_t buf[13] = {0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[19];
    bool success = decode->translate(buf, 13, decode_int7, bytes_processed, res, 19, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 13);
    CHECK(bytes_written == 15);
    CHECK(memcmp(res, "www.example.com", 15) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_rfc_example2)
{
    // prepare buf to decode - Huffman "no-cache" , RFC c.4.2
    uint8_t buf[7] = {0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[9];
    bool success = decode->translate(buf, 7, decode_int7, bytes_processed, res, 9, bytes_written, &events, &inf,
        false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 7);
    CHECK(bytes_written == 8);
    CHECK(memcmp(res, "no-cache", 8) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_rfc_example3)
{
    // prepare buf to decode - Huffman "custom-key" , RFC c.4.3
    uint8_t buf[9] = {0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[12];
    bool success = decode->translate(buf, 9, decode_int7, bytes_processed, res, 12, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 9);
    CHECK(bytes_written == 10);
    CHECK(memcmp(res, "custom-key", 10) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_rfc_example4)
{
    // prepare buf to decode - Huffman "custom-value" , RFC c.4.3
    uint8_t buf[10] = {0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[14];
    bool success = decode->translate(buf, 10, decode_int7, bytes_processed, res, 14, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 10);
    CHECK(bytes_written == 12);
    CHECK(memcmp(res, "custom-value", 12) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_rfc_example5)
{
    // prepare buf to decode - Huffman "Mon, 21 Oct 2013 20:13:21 GMT" , RFC c.6.1
    uint8_t buf[23] = {0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20,
        0x05, 0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[35];
    bool success = decode->translate(buf, 23, decode_int7, bytes_processed, res, 35, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 23);
    CHECK(bytes_written == 29);
    CHECK(memcmp(res, "Mon, 21 Oct 2013 20:13:21 GMT", 29) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_rfc_example6)
{
    // prepare buf to decode - Huffman "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" , RFC c.6.3
    uint8_t buf[46] = {0xad, 0x94, 0xe7, 0x82, 0x1d, 0xd7, 0xf2, 0xe6, 0xc7, 0xb3, 0x35, 0xdf,
        0xdf, 0xcd, 0x5b, 0x39, 0x60, 0xd5, 0xaf, 0x27, 0x08, 0x7f, 0x36, 0x72,
        0xc1, 0xab, 0x27, 0x0f, 0xb5, 0x29, 0x1f, 0x95, 0x87, 0x31, 0x60, 0x65,
        0xc0, 0x03, 0xed, 0x4e, 0xe5, 0xb1, 0x06, 0x3d, 0x50, 0x07};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[73];
    bool success = decode->translate(buf, 46, decode_int7, bytes_processed, res, 73, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 46);
    CHECK(bytes_written == 56);
    CHECK(memcmp(res, "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", 56) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_unaligned_then_aligned)
{
    // prepare buf to decode - Huffman first 4 symbols are 6 bit each, followed by 8 bit
    uint8_t buf[5] = {0x84, 0x59, 0x76, 0x19, 0xfa};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[6];
    bool success = decode->translate(buf, 5, decode_int7, bytes_processed, res, 6, bytes_written, &events, &inf,
        false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 5);
    CHECK(bytes_written == 5);
    CHECK(memcmp(res, "-./3,", 5) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_decoding_all_possible_symbols_1)
{
    // prepare buf to decode - "abcdefghijklmnopqrstuvwxyz"
    uint8_t buf[21] = {0x94, 0x1c, 0x64, 0x90, 0xb2, 0xcd, 0x39, 0xba, 0x75, 0xa2, 0x9a, 0x8f, 0x5f, 0x6b,
        0x10, 0x9b, 0x7b, 0xf8, 0xf3, 0xeb, 0xdf};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[32];
    bool success = decode->translate(buf, 21, decode_int7, bytes_processed, res, 32, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 21);
    CHECK(bytes_written == 26);
    CHECK(memcmp(res, "abcdefghijklmnopqrstuvwxyz", 26) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_decoding_all_possible_symbols_2)
{
    // prepare buf to decode - "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    uint8_t buf[24] = {0x97, 0x86, 0xed, 0xeb, 0xf8, 0x30, 0xe2, 0xc7, 0x93, 0x2e, 0x6c, 0xfa, 0x34, 0xea,
        0xd7, 0xb3, 0x6e, 0xed, 0xfc, 0x38, 0xf2, 0xfc, 0xe7, 0xfb};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[36];
    bool success = decode->translate(buf, 24, decode_int7, bytes_processed, res, 36, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 24);
    CHECK(bytes_written == 26);
    CHECK(memcmp(res, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_decoding_all_possible_symbols_3)
{
    // prepare buf to decode - "0123456789"
    uint8_t buf[9] = {0x88, 0x00, 0x44, 0xcb, 0x4d, 0xb8, 0xeb, 0xcf, 0xff};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[12];
    bool success = decode->translate(buf, 9, decode_int7, bytes_processed, res, 12, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 9);
    CHECK(bytes_written == 10);
    CHECK(memcmp(res, "0123456789", 10) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_decoding_all_possible_symbols_4)
{
    // prepare buf to decode - ' !"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~'
  uint8_t buf[45] = {0xAC, 0x53, 0xF8, 0xFE, 0x7F, 0xEB, 0xFF, 0x2A, 0xFC, 0X7F, 0xAF, 0xEB, 0xFB, 0xF9,
      0xFF, 0x7F, 0x4B, 0x2E, 0xC5, 0xCF, 0xBF, 0xFF, 0x90, 0x7F, 0xDF, 0xF9, 0xFF, 0xAF, 0xFD, 0xFF, 0xFF,
      0x0F, 0xFE, 0x7F, 0xF9, 0x17, 0xFF, 0xDF, 0xFF, 0xDF, 0xF3, 0xFF, 0xDF, 0xFE, 0xFF};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[70];
    bool success = decode->translate(buf, 45, decode_int7, bytes_processed, res, 70, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 45);
    CHECK(bytes_written == 33);
    CHECK(memcmp(res, " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 33) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_decoding_all_possible_symbols_hex_00_0F)
{
    // prepare buf to decode - encoded 0x00-0x0F
  uint8_t buf[55] = {0xB6, 0xFF, 0xC7, 0xFF, 0xFD, 0x8F, 0xFF, 0xFF, 0xE2, 0xFF, 0xFF, 0xFE, 0x3F, 0xFF,
      0xFF, 0xE4, 0xFF, 0xFF, 0xFE, 0x5F, 0xFF, 0xFF, 0xE6, 0xFF, 0xFF, 0xFE, 0x7F, 0xFF, 0xFF, 0xE8, 0xFF,
      0xFF, 0xEA, 0xFF, 0xFF, 0xFF, 0xF3, 0xFF, 0xFF, 0xFA, 0x7F, 0xFF, 0xFF, 0xAB, 0xFF, 0xFF, 0xFF, 0xDF,
      0xFF, 0xFF, 0xEB, 0xFF, 0xFF, 0xFE, 0xCF};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[88];
    uint8_t expected[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    bool success = decode->translate(buf, 55, decode_int7, bytes_processed, res, 88, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 55);
    CHECK(bytes_written == 16);
    CHECK(memcmp(res, expected, 16) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_decoding_all_possible_symbols_hex_10_1F)
{
    // prepare buf to decode - encoded 0x10-0x1F
  uint8_t buf[58] = {0xB9, 0xFF, 0xFF, 0xFE, 0xDF, 0xFF, 0xFF, 0xEE, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
      0xF0, 0xFF, 0xFF, 0xFF, 0x1F, 0xFF, 0xFF, 0xF2, 0xFF, 0xFF, 0xFF, 0xFB, 0xFF, 0xFF, 0xFC, 0xFF, 0xFF,
      0xFF, 0xD3, 0xFF, 0xFF, 0xFD, 0x7F, 0xFF, 0xFF, 0xDB, 0xFF, 0xFF, 0xFD, 0xFF, 0xFF, 0xFF, 0xE3, 0xFF,
      0xFF, 0xFE, 0x7F, 0xFF, 0xFF, 0xEB, 0xFF, 0xFF, 0xFE, 0xFF};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[93];
    uint8_t expected[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    bool success = decode->translate(buf, 58, decode_int7, bytes_processed, res, 93, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 58);
    CHECK(bytes_written == 16);
    CHECK(memcmp(res, expected, 16) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_decoding_all_possible_symbols_hex_7F_8F)
{
    // prepare buf to decode - encoded 0x7F-0x8F
  uint8_t buf[49] = {0xB0, 0xFF, 0xFF, 0xFF, 0xCF, 0xFF, 0xE6, 0xFF, 0xFF, 0x4B, 0xFF, 0xF9, 0xFF, 0xFF,
      0xA3, 0xFF, 0xFD, 0x3F, 0xFF, 0xF5, 0x3F, 0xFF, 0xD5, 0xFF, 0xFF, 0xB3, 0xFF, 0xFE, 0xB7, 0xFF, 0xFD,
      0xAF, 0xFF, 0xFB, 0x7F, 0xFF, 0xF7, 0x3F, 0xFF, 0xEE, 0xFF, 0xFF, 0xDE, 0xFF, 0xFF, 0xEB, 0xFF, 0xFF,
      0xBF};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[79];
    uint8_t expected[17] = {0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F};
    bool success = decode->translate(buf, 49, decode_int7, bytes_processed, res, 79, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 49);
    CHECK(bytes_written == 17);
    CHECK(memcmp(res, expected, 17) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_decoding_all_possible_symbols_hex_90_9F)
{
    // prepare buf to decode - encoded 0x90-0x9F
  uint8_t buf[47] = {0xAE, 0xFF, 0xFF, 0xEC, 0xFF, 0xFF, 0xED, 0xFF, 0xFF, 0x5F, 0xFF, 0xFF, 0x07, 0xFF,
      0xFF, 0x77, 0xFF, 0xFE, 0x1F, 0xFF, 0xFC, 0x5F, 0xFF, 0xF8, 0xFF, 0xFF, 0xF2, 0x7F, 0xFF, 0x73, 0xFF,
      0xFD, 0x8F, 0xFF, 0xFC, 0xBF, 0xFF, 0xEC, 0xFF, 0xFF, 0xE6, 0xFF, 0xFF, 0xCF, 0xFF, 0xFF, 0xDF};

    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[76];
    uint8_t expected[16] = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F};
    bool success = decode->translate(buf, 47, decode_int7, bytes_processed, res, 76, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 47);
    CHECK(bytes_written == 16);
    CHECK(memcmp(res, expected, 16) == 0);
}
TEST(http2_hpack_string_decode_success, huffman_decoding_all_possible_symbols_hex_A0_AF)
{
    // prepare buf to decode - encoded 0xA0-0xAF
  uint8_t buf[46] = {0xAD, 0xFF, 0xFF, 0x6B, 0xFF, 0xFB, 0xBF, 0xFF, 0xD3, 0xFF, 0xFE, 0xDF, 0xFF, 0xFB,
      0x9F, 0xFF, 0xFA, 0x3F, 0xFF, 0xF4, 0xFF, 0xFF, 0x7B, 0xFF, 0xFF, 0x57, 0xFF, 0xFB, 0xBF, 0xFF, 0xEF,
      0x7F, 0xFF, 0xF8, 0x7F, 0xFF, 0x7F, 0xFF, 0xFD, 0xFF, 0xFF, 0xFD, 0x7F, 0xFF, 0xFB, 0x3F};

    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[74];
    uint8_t expected[16] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};
    bool success = decode->translate(buf, 46, decode_int7, bytes_processed, res, 74, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 46);
    CHECK(bytes_written == 16);
    CHECK(memcmp(res, expected, 16) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_decoding_all_possible_symbols_hex_B0_BF)
{
    // prepare buf to decode - encoded 0xB0-0xBF
  uint8_t buf[45] = {0xAC, 0xFF, 0xFF, 0x07, 0xFF, 0xF8, 0x7F, 0xFF, 0xE0, 0xFF, 0xFF, 0x17, 0xFF, 0xFE,
      0xDF, 0xFF, 0xF8, 0x7F, 0xFF, 0xF7, 0x7F, 0xFF, 0xEF, 0xFF, 0xFE, 0xAF, 0xFF, 0xF8, 0xBF, 0xFF, 0xE3,
      0xFF, 0xFF, 0x93, 0xFF, 0xFF, 0x87, 0xFF, 0xFC, 0xBF, 0xFF, 0xF3, 0x7F, 0xFF, 0xF1};

    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[73];
    uint8_t expected[16] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF};
    bool success = decode->translate(buf, 45, decode_int7, bytes_processed, res, 73, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 45);
    CHECK(bytes_written == 16);
    CHECK(memcmp(res, expected, 16) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_decoding_all_possible_symbols_hex_C0_CF)
{
    // prepare buf to decode - encoded 0xC0-0xCF
  uint8_t buf[50] = {0xB1, 0xFF, 0xFF, 0xF8, 0x3F, 0xFF, 0xFE, 0x1F, 0xFF, 0xEB, 0xFF, 0xFE, 0x3F, 0xFF,
      0xF3, 0xFF, 0xFF, 0xF2, 0xFF, 0xFF, 0xA3, 0xFF, 0xFF, 0xD9, 0xFF, 0xFF, 0xF1, 0x7F, 0xFF, 0xFC, 0x7F,
      0xFF, 0xFF, 0x27, 0xFF, 0xFF, 0xDE, 0xFF, 0xFF, 0xFB, 0xFF, 0xFF, 0xFF, 0x2F, 0xFF, 0xFF, 0x8F, 0xFF,
      0xFF, 0xB7};

    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[80];
    uint8_t expected[16] = {0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF};
    bool success = decode->translate(buf, 50, decode_int7, bytes_processed, res, 80, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 50);
    CHECK(bytes_written == 16);
    CHECK(memcmp(res, expected, 16) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_decoding_all_possible_symbols_hex_D0_DF)
{
    // prepare buf to decode - encoded 0xD0-0xDF
  uint8_t buf[51] = {0xB2, 0xFF, 0xFE, 0x5F, 0xFF, 0xE3, 0xFF, 0xFF, 0xF9, 0xBF, 0xFF, 0xFF, 0x07, 0xFF,
      0xFF, 0xE1, 0xFF, 0xFF, 0xF9, 0xFF, 0xFF, 0xFF, 0x17, 0xFF, 0xFF, 0x97, 0xFF, 0xF9, 0x3F, 0xFF, 0xCB,
      0xFF, 0xFF, 0xF4, 0x7F, 0xFF, 0xFD, 0x3F, 0xFF, 0xFF, 0xFB, 0xFF, 0xFF, 0xF8, 0xFF, 0xFF, 0xFF, 0x27,
      0xFF, 0xFF, 0xE5};

    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[82];
    uint8_t expected[16] = {0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF};
    bool success = decode->translate(buf, 51, decode_int7, bytes_processed, res, 82, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 51);
    CHECK(bytes_written == 16);
    CHECK(memcmp(res, expected, 16) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_decoding_all_possible_symbols_hex_E0_EF)
{
    // prepare buf to decode - encoded 0xE0-0xEF
  uint8_t buf[47] = {0xAE, 0xFF, 0xFE, 0xCF, 0xFF, 0xFF, 0x3F, 0xFF, 0xED, 0xFF, 0xFF, 0x37, 0xFF, 0xFD,
      0x3F, 0xFF, 0xE7, 0xFF, 0xFF, 0x47, 0xFF, 0xFF, 0x3F, 0xFF, 0xFA, 0xBF, 0xFF, 0xEB, 0xFF, 0xFF, 0xF7,
      0x7F, 0xFF, 0xFB, 0xFF, 0xFF, 0xFD, 0x3F, 0xFF, 0xFD, 0x7F, 0xFF, 0xFE, 0xAF, 0xFF, 0xFE, 0x9F};

    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[76];
    uint8_t expected[16] = {0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF};
    bool success = decode->translate(buf, 47, decode_int7, bytes_processed, res, 76, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 47);
    CHECK(bytes_written == 16);
    CHECK(memcmp(res, expected, 16) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_decoding_all_possible_symbols_hex_F0_FF)
{
    // prepare buf to decode - encoded 0xF0-0xFF
  uint8_t buf[55] = {0xB6, 0xFF, 0xFF, 0xFA, 0xFF, 0xFF, 0xFF, 0x37, 0xFF, 0xFF, 0xD9, 0xFF, 0xFF, 0xF6,
      0xFF, 0xFF, 0xFE, 0x7F, 0xFF, 0xFF, 0xD1, 0xFF, 0xFF, 0xFA, 0x7F, 0xFF, 0xFF, 0x57, 0xFF, 0xFF, 0xEB,
      0xFF, 0xFF, 0xFF, 0xEF, 0xFF, 0xFF, 0xD9, 0xFF, 0xFF, 0xFB, 0x7F, 0xFF, 0xFF, 0x77, 0xFF, 0xFF, 0xEF,
      0xFF, 0xFF, 0xFE, 0x1F, 0xFF, 0xFF, 0x77};

    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[88];
    uint8_t expected[16] = {0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF};
    bool success = decode->translate(buf, 55, decode_int7, bytes_processed, res, 88, bytes_written, &events,
        &inf, false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 55);
    CHECK(bytes_written == 16);
    CHECK(memcmp(res, expected, 16) == 0);
}

TEST(http2_hpack_string_decode_success, huffman_decoding_tail_lookup_unsucessful)
{
    // tail lookup unsuccessful after successful previous match
    // decodes to 9D
    uint8_t buf[3] = {0x82, 0x7E, 0xFF};
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[3];
    bool success = decode->translate(buf, 3, decode_int7, bytes_processed, res, 3, bytes_written, &events, &inf,
        false);
    // check results
    CHECK(success == true);
    CHECK(bytes_processed == 3);
    CHECK(bytes_written == 2);
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
    Http2HpackStringDecode local_decode;
    Http2HpackIntDecode decode_int7(7);

    // prepare buf to decode - use field length 0
    uint8_t buf = 0;
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res;
    bool success = local_decode.translate(&buf, 0, decode_int7, bytes_processed, &res, 1, bytes_written,
        &local_events, &local_inf, false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 0);
    CHECK(bytes_written == 0);
    CHECK(local_inf.get_raw(0) == (1<<INF_STRING_EMPTY_BUFF));
}

TEST(http2_hpack_string_decode_infractions, missing_bytes)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode;
    Http2HpackIntDecode decode_int7(7);
    // prepare buf to decode - length is 1, no string
    uint8_t buf = 1;
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[2];
    bool success = local_decode.translate(&buf, 1, decode_int7, bytes_processed, res, 2, bytes_written,
        &local_events, &local_inf, false);
    // check results
    CHECK(success == false);
    CHECK(bytes_written == 0);
    CHECK(bytes_processed == 1);
    CHECK(local_inf.get_raw(0) == (1<<INF_STRING_MISSING_BYTES));
}

TEST(http2_hpack_string_decode_infractions, bad_int)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode;
    Http2HpackIntDecode decode_int7(7);
    // prepare buf to decode - bad int
    uint8_t buf[2] = { 0x7f, 0x80 };
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[2];
    bool success = local_decode.translate(buf, 2, decode_int7, bytes_processed, res, 2, bytes_written,
        &local_events, &local_inf, false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 2);
    CHECK(bytes_written == 0);
    CHECK(local_inf.get_raw(0) == (1<<INF_INT_MISSING_BYTES));
}

TEST(http2_hpack_string_decode_infractions, max_field_length_plus_1)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode;
    Http2HpackIntDecode decode_int7(7);
    // prepare buf to decode -  int + string == MAX_OCTETS+1 (Field limitation + 1)
    uint8_t buf[MAX_OCTETS];
    buf[0] = 0x7F;
    buf[1] = 0xA2;
    buf[2] = 0xF1;
    buf[3]= 0x3;
    memset(&buf[4], 'A', MAX_OCTETS-4);
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[MAX_OCTETS];
    bool success = local_decode.translate(buf, MAX_OCTETS, decode_int7, bytes_processed, res,
        MAX_OCTETS, bytes_written, &local_events, &local_inf, false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 4);
    CHECK(bytes_written == 0);
    CHECK(local_inf.get_raw(0) == (1<<INF_STRING_MISSING_BYTES));
}

TEST(http2_hpack_string_decode_infractions, out_buf_out_of_space)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode;
    Http2HpackIntDecode decode_int7(7);
    // prepare buf to decode
    uint8_t buf[MAX_OCTETS];
    buf[0] = 0x7F;
    buf[1] = 0xA1;
    buf[2] = 0xF1;
    buf[3]= 0x3;
    memset(&buf[4], 'A', MAX_OCTETS-4);
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[MAX_OCTETS-5];
    bool success = local_decode.translate(buf, MAX_OCTETS, decode_int7, bytes_processed, res,
        MAX_OCTETS-5, bytes_written, &local_events, &local_inf, false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 4);
    CHECK(bytes_written == 0);
    CHECK(local_inf.get_raw(0) == (1<<INF_DECODED_HEADER_BUFF_OUT_OF_SPACE));
}

TEST(http2_hpack_string_decode_infractions, huffman_1_byte_bad_padding)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode;
    Http2HpackIntDecode decode_int7(7);
    // prepare buf to decode - bad padding
    uint8_t buf[2] = { 0x81, 0x54 };
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[2];
    bool success = local_decode.translate(buf, 2, decode_int7, bytes_processed, res, 2, bytes_written,
        &local_events, &local_inf, false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 2);
    CHECK(bytes_written == 1);
    CHECK(local_inf.get_raw(0) == (1<<INF_HUFFMAN_BAD_PADDING));
}

TEST(http2_hpack_string_decode_infractions, huffman_1_byte_incomplete_FF)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode;
    Http2HpackIntDecode decode_int7(7);
    // prepare buf to decode - Incomplete code 0xFF
    uint8_t buf[2] = { 0x81, 0xFF };
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[2];
    bool success = local_decode.translate(buf, 2, decode_int7, bytes_processed, res, 2, bytes_written,
        &local_events, &local_inf, false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 2);
    CHECK(bytes_written == 0);
    CHECK(local_inf.get_raw(0) == (1<<INF_HUFFMAN_INCOMPLETE_CODE_PADDING));
}

TEST(http2_hpack_string_decode_infractions, huffman_1_byte_incomplete_FE)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode;
    Http2HpackIntDecode decode_int7(7);
    // prepare buf to decode - Incomplete code 0xFE
    uint8_t buf[2] = { 0x81, 0xFE };
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[2];
    bool success = local_decode.translate(buf, 2, decode_int7, bytes_processed, res, 2, bytes_written,
        &local_events, &local_inf, false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 2);
    CHECK(bytes_written == 0);
    CHECK(local_inf.get_raw(0) == (1<<INF_HUFFMAN_INCOMPLETE_CODE_PADDING));
}

TEST(http2_hpack_string_decode_infractions, huffman_2_bytes_incomplete_FF_FE)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode;
    Http2HpackIntDecode decode_int7(7);
    // prepare buf to decode - Incomplete code 0xFFFE
    uint8_t buf[3] = { 0x82, 0xFF, 0xFE };
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[5];
    bool success = local_decode.translate(buf, 3, decode_int7, bytes_processed, res, 5, bytes_written,
        &local_events, &local_inf, false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 3);
    CHECK(bytes_written == 0);
    CHECK(local_inf.get_raw(0) == (1<<INF_HUFFMAN_INCOMPLETE_CODE_PADDING));
}

TEST(http2_hpack_string_decode_infractions, huffman_3_bytes_incomplete)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode;
    Http2HpackIntDecode decode_int7(7);
    // prepare buf to decode - Incomplete code 0xFFFFFE
    uint8_t buf[4] = { 0x83, 0xFF, 0xFF, 0xFE };
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[7];
    bool success = local_decode.translate(buf, 4, decode_int7, bytes_processed, res, 7, bytes_written,
        &local_events, &local_inf, false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 4);
    CHECK(bytes_written == 0);
    CHECK(local_inf.get_raw(0) == (1<<INF_HUFFMAN_INCOMPLETE_CODE_PADDING));
}

TEST(http2_hpack_string_decode_infractions, huffman_FB_incomplete_FF)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode;
    Http2HpackIntDecode decode_int7(7);
    // prepare buf to decode - ';' (8 bits) and incomplete code 0xFF
    uint8_t buf[3] = { 0x82, 0xFB, 0xFF };
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[5];
    bool success = local_decode.translate(buf, 3, decode_int7, bytes_processed, res, 5, bytes_written,
        &local_events, &local_inf, false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 3);
    CHECK(bytes_written == 1);
    CHECK(local_inf.get_raw(0) == (1<<INF_HUFFMAN_INCOMPLETE_CODE_PADDING));
    CHECK(memcmp(res, ";", 1) == 0);
}

TEST(http2_hpack_string_decode_infractions, huffman_07_incomplete_FF)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode;
    Http2HpackIntDecode decode_int7(7);
    // prepare buf to decode - '0' (5 bits) and incomplete code 0xFF with padding
    uint8_t buf[3] = { 0x82, 0x07, 0xFF };
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[5];
    bool success = local_decode.translate(buf, 3, decode_int7, bytes_processed, res, 5, bytes_written,
        &local_events, &local_inf, false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 3);
    CHECK(bytes_written == 1);
    CHECK(local_inf.get_raw(0) == (1<<INF_HUFFMAN_INCOMPLETE_CODE_PADDING));
    CHECK(memcmp(res, "0", 1) == 0);
}

TEST(http2_hpack_string_decode_infractions, huffman_decoded_eos)
{
    // prepare decode object
    Http2EventGen local_events;
    Http2Infractions local_inf;
    Http2HpackStringDecode local_decode;
    Http2HpackIntDecode decode_int7(7);
    // prepare buf to decode - bad padding
    uint8_t buf[5] = { 0x84, 0xFF, 0xFF, 0xFF, 0xFF };
    // decode
    uint32_t bytes_processed = 0, bytes_written = 0;
    uint8_t res[10];
    bool success = local_decode.translate(buf, 5, decode_int7, bytes_processed, res, 10, bytes_written,
        &local_events, &local_inf, false);
    // check results
    CHECK(success == false);
    CHECK(bytes_processed == 4);
    CHECK(bytes_written == 0);
    CHECK(local_inf.get_raw(0) == (1<<INF_HUFFMAN_DECODED_EOS));
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

