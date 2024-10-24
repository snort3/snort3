//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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

// http2_hpack_test.cc author Jaime Andres Castillo <jaimeaca@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <map>
#include <algorithm>

#include "../../../flow/flow_data.h"
#include "../../../framework/counts.h"
#include "../../http_inspect/http_field.h"
#include "../../http_inspect/http_test_manager.h"

#include "../http2_enum.h"
#include "../http2_flow_data.h"
#include "../http2_hpack.h"
#include "../http2_hpack_cookie_header_buffer.h"
#include "../http2_hpack_dynamic_table.h"
#include "../http2_hpack_int_decode.h"
#include "../http2_module.h"
#include "../http2_request_line.h"
#include "../http2_settings_frame.h"


#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>


int snort::DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
long HttpTestManager::print_amount {};
bool HttpTestManager::print_hex {};

snort::FlowData::~FlowData() = default;
snort::FlowData::FlowData(unsigned int, snort::Inspector*) { }
THREAD_LOCAL PegCount Http2Module::peg_counts[Http2Enums::PEG_COUNT__MAX] = { };
uint32_t Http2ConnectionSettings::get_param(uint16_t) { return 42; }
Http2DataCutter::Http2DataCutter(Http2FlowData* _session_data, HttpCommon::SourceId src_id)
    : session_data(_session_data), source_id(src_id) { }
Http2Stream::~Http2Stream() = default;
Http2FlowData::Http2FlowData(snort::Flow* flow_)
    : snort::FlowData(0, nullptr) , flow(flow_) , hi(nullptr)
    , hpack_decoder {
        Http2HpackDecoder(this, HttpCommon::SRC_CLIENT, events[HttpCommon::SRC_CLIENT], infractions[HttpCommon::SRC_CLIENT]),
        Http2HpackDecoder(this, HttpCommon::SRC_SERVER, events[HttpCommon::SRC_SERVER], infractions[HttpCommon::SRC_SERVER])
    }
    , data_cutter { Http2DataCutter(this, HttpCommon::SRC_CLIENT), Http2DataCutter(this, HttpCommon::SRC_SERVER) }
{ }
Http2FlowData::~Http2FlowData()
{
    delete infractions[0];
    delete infractions[1];

    delete events[0];
    delete events[1];
}


TEST_GROUP(http2_hpack_cookie_header_buffer)
{
    using u8string = std::basic_string<uint8_t>;

    Http2CookieHeaderBuffer cookie_buffer;
    // constant arrays used in several tests
    const u8string cookie_key = (uint8_t*)"cookie";
    const uint32_t cookie_line_offset = u8string(cookie_key + (uint8_t*)": \r\n").length();

    struct TestBuffer
    {
    public:
        TestBuffer(u8string headers_content, uint32_t max_buffer_size)
            : max_buffer_size(max_buffer_size), headers_buffer(new uint8_t[max_buffer_size])
            , headers_buffer_size(headers_content.length())
        {
            std::copy(headers_content.begin(), headers_content.end(), headers_buffer.get());
        }

        uint32_t max_buffer_size = 0;
        std::unique_ptr<uint8_t[]> headers_buffer = nullptr;
        uint32_t headers_buffer_size = 0;
        Http2Infractions infra;
    };

    struct DecodedBuffer
    {
        explicit DecodedBuffer(uint32_t capacity)
            : decoded_header_capacity(capacity), decoded_header_buffer(new uint8_t[capacity])
        {}
        uint32_t decoded_header_capacity = 1024;
        uint32_t decoded_header_length = 0;
        uint32_t bytes_written = 0;
        std::unique_ptr<uint8_t[]> decoded_header_buffer;
        Http2Infractions infra;
    };

    void setup() override
    {
    }
    void teardown() override
    {
    }
};

// Ensure overflow situation get an INF_DECODED_HEADER_BUFF_OUT_OF_SPACE infraction
TEST(http2_hpack_cookie_header_buffer, append_to_header_line_cause_overflow_in_decoded_buffer)
{
    // arrange
    // create buffer, initialize content and set capacity
    TestBuffer buffer((uint8_t*)"", 5);
    u8string cookie_value = (uint8_t*)"n=value";
    cookie_buffer.append_value(cookie_value.c_str(), cookie_value.length());
    // act
    uint32_t bytes_written = 0;
    bool success =cookie_buffer.append_header_in_decoded_headers(
        buffer.headers_buffer.get(), buffer.headers_buffer_size, buffer.max_buffer_size,
        bytes_written, &buffer.infra);
    buffer.headers_buffer_size += bytes_written;
    // assert
    CHECK(bytes_written == 0);
    CHECK(success == false);
    using hi = Http2Enums::Infraction;
    CHECK(buffer.infra & hi::INF_DECODED_HEADER_BUFF_OUT_OF_SPACE);
    u8string expected_headers_value = (uint8_t*)"";
    u8string headers_value(buffer.headers_buffer.get(), buffer.headers_buffer_size);
    CHECK(headers_value == expected_headers_value);
}

// Ensure cookies can be added to empty decoded buffer and no separator added
TEST(http2_hpack_cookie_header_buffer, append_to_header_line_in_empty_decoded_buffer)
{
    // arrange
    // create buffer, initialize content and set capacity
    TestBuffer buffer((uint8_t*)"", 1000);
    u8string cookie_value = (uint8_t*)"n=value";

    cookie_buffer.append_value(cookie_value.c_str(), cookie_value.length());
    // act
    uint32_t bytes_written = 0;
    cookie_buffer.append_header_in_decoded_headers(
        buffer.headers_buffer.get(), buffer.headers_buffer_size, buffer.max_buffer_size,
        bytes_written, &buffer.infra);
    buffer.headers_buffer_size += bytes_written;
    // assert
    CHECK(bytes_written == cookie_line_offset + cookie_value.length());
    u8string expected_headers_value = (uint8_t*)"cookie: n=value\r\n";
    u8string headers_value(buffer.headers_buffer.get(), buffer.headers_buffer_size);
    CHECK(headers_value == expected_headers_value);
}

// Ensure cookies can be added to non-empty decoded buffer and no separator added
TEST(http2_hpack_cookie_header_buffer, append_to_header_line_at_end_of_decoded_buffer)
{
    // arrange
    u8string headers_content = (uint8_t*)"accept: *\r\naccept-language: en-US,en;q=0.9\r\n";
    const uint32_t max_buffer_size = 1000;
    TestBuffer buffer(headers_content, max_buffer_size);
    u8string cookie_value = (uint8_t*)"n=value";
    cookie_buffer.append_value(cookie_value.c_str(), cookie_value.length());
    // act
    uint32_t bytes_written = 0;
    cookie_buffer.append_header_in_decoded_headers(
        buffer.headers_buffer.get(), buffer.headers_buffer_size, max_buffer_size,
        bytes_written, &buffer.infra);
    buffer.headers_buffer_size += bytes_written;
    // assert
    CHECK(bytes_written == cookie_line_offset + cookie_value.length());
    u8string expected_headers_value = (uint8_t*)"accept: *\r\n"
                                                "accept-language: en-US,en;q=0.9\r\n"
                                                "cookie: n=value\r\n";
    u8string headers_value(buffer.headers_buffer.get(), buffer.headers_buffer_size);
    CHECK(headers_value == expected_headers_value);
}

// Ensure appended headers are separated by "; ", and the last one a "\r\n"
TEST(http2_hpack_cookie_header_buffer, appending_separators_to_multiple_cookies_one_by_one)
{
    // arrange
    DecodedBuffer buf(1024);
    u8string value1 = (uint8_t*)"n1=value1";
    u8string value2 = (uint8_t*)"n2=value2";
    u8string value3 = (uint8_t*)"n3=value3";
    // act
    cookie_buffer.append_value(value1.c_str(), value1.length());
    cookie_buffer.append_value(value2.c_str(), value2.length());
    cookie_buffer.append_value(value3.c_str(), value3.length());
    cookie_buffer.append_header_in_decoded_headers(buf.decoded_header_buffer.get(),
        buf.decoded_header_length, buf.decoded_header_capacity, buf.bytes_written, &buf.infra);
    // assert
    u8string expected_cookie_header_line = (uint8_t*)"cookie: n1=value1; n2=value2; n3=value3\r\n";
    u8string cookie_header_line(buf.decoded_header_buffer.get(), buf.bytes_written);
    CHECK(cookie_header_line == expected_cookie_header_line);
}

// Ensure appended headers are separated by "; ", even when finishing in ";"
TEST(http2_hpack_cookie_header_buffer, appending_separators_to_ended_semicolon_and_appending_multiple)
{
    // arrange
    DecodedBuffer buf(1024);
    u8string value = (uint8_t*)"n=value;";
    u8string valueN = (uint8_t*)"n1=value1; n2=value2; n3=value3";
    // act
    cookie_buffer.append_value(value.c_str(), value.length());
    cookie_buffer.append_value(valueN.c_str(), valueN.length());
    cookie_buffer.append_header_in_decoded_headers(buf.decoded_header_buffer.get(),
        buf.decoded_header_length, buf.decoded_header_capacity, buf.bytes_written, &buf.infra);
    // assert
    u8string expected_cookie_header_line = (uint8_t*)"cookie: n=value;; n1=value1; n2=value2; n3=value3\r\n";
    u8string cookie_header_line(buf.decoded_header_buffer.get(), buf.bytes_written);
    CHECK(cookie_header_line == expected_cookie_header_line);
}

// Ensure appended headers are separated by "; ", even when finishing in "; "
TEST(http2_hpack_cookie_header_buffer, appending_separators_to_ended_semicolon_space_and_appending_multiple)
{
    // arrange
    DecodedBuffer buf(1024);
    u8string value = (uint8_t*)"n=value; ";
    u8string valueN = (uint8_t*)"n1=value1; n2=value2; n3=value3";
    // act
    cookie_buffer.append_value(value.c_str(), value.length());
    cookie_buffer.append_value(valueN.c_str(), valueN.length());
    cookie_buffer.append_header_in_decoded_headers(buf.decoded_header_buffer.get(),
        buf.decoded_header_length, buf.decoded_header_capacity, buf.bytes_written, &buf.infra);
    // assert
    u8string expected_cookie_header_line = (uint8_t*)"cookie: n=value; ; n1=value1; n2=value2; n3=value3\r\n";
    u8string cookie_header_line(buf.decoded_header_buffer.get(), buf.bytes_written);
    CHECK(cookie_header_line == expected_cookie_header_line);
}

TEST_GROUP(http2_hpack_decoder_decode_header_buffers)
{
    using u8string = std::basic_string<uint8_t>;

    Http2EventGen* const events[2] = { new Http2EventGen, new Http2EventGen };
    Http2Infractions* const infractions[2] = { new Http2Infractions, new Http2Infractions };
    Http2HpackDecoder* hpack_decoder;
    Http2StartLine* start_client_line;
    Http2FlowData* session_data = new Http2FlowData(nullptr);

    void setup() override
    {
        hpack_decoder = new Http2HpackDecoder(session_data, HttpCommon::SRC_CLIENT, events[HttpCommon::SRC_CLIENT], infractions[HttpCommon::SRC_CLIENT]);
        start_client_line = new Http2RequestLine(events[0], infractions[0]);
    }
    void teardown() override
    {
        delete session_data;
        delete start_client_line;

        delete hpack_decoder;

        delete infractions[0];
        delete infractions[1];

        delete events[0];
        delete events[1];
    }
};

// Ensure headers with no cookies are kept the same example with pseudoheaders
TEST(http2_hpack_decoder_decode_header_buffers, simple_test_pseudoheaders_no_cookies)
{
    // arrange
    const uint8_t encoded_headers[] = {
        0x82,
        0x84,
        0x41, 0xc, 'w', 'w', 'w', '.', 't', 'e', 's', 't', '.', 'c', 'o', 'm',
        0x86,
        0x53, 0x03, 0x2a, 0x2f, 0x2a, 
        0x50, 0x8d, 0x9b, 0xd9, 0xab, 0xfa, 0x52, 0x42, 0xcb, 0x40, 0xd2, 0x5f, 0xa5, 0x23, 0xb3,
        0x51, 0x8b, 0x2d, 0x4b, 0x70, 0xdd, 0xf4, 0x5a, 0xbe, 0xfb, 0x40, 0x05, 0xdf
    };
    const uint32_t encoded_headers_length {sizeof(encoded_headers)/sizeof(const uint8_t)};
    u8string expected_headers_str = 
        (uint8_t*)  "accept: */*\r\n"
                    "accept-encoding: gzip, deflate, br\r\n"
                    "accept-language: en-US,en;q=0.9\r\n"
                    "\r\n";
    Field http1_header;
    bool trailers {false};
    // act
    bool success = hpack_decoder->decode_headers((
        const uint8_t*)encoded_headers, encoded_headers_length, start_client_line, trailers);
    hpack_decoder->set_decoded_headers(http1_header);
    // assert
    CHECK(success == true);
    u8string headers_str(http1_header.start(), http1_header.start() + http1_header.length());
    CHECK(expected_headers_str == headers_str);
}

// Ensure headers with no cookies are kept the same
TEST(http2_hpack_decoder_decode_header_buffers, simple_header_with_no_cookies)
{
    // arrange
    const uint8_t encoded_headers[] = {
        0x53, 0x01, 0x2a, 
    };
    const uint32_t encoded_headers_length {sizeof(encoded_headers)/sizeof(const uint8_t)};
    u8string expected_headers_str = 
        (uint8_t*)  "accept: *\r\n"
                    "\r\n";
    Field http1_header;
    bool trailers {false};
    // act
    bool success = hpack_decoder->decode_headers((
        const uint8_t*)encoded_headers, encoded_headers_length, start_client_line, trailers);
    hpack_decoder->set_decoded_headers(http1_header);
    // assert
    CHECK(success == true);
    u8string headers_str(http1_header.start(), http1_header.start() + http1_header.length());
    CHECK(expected_headers_str == headers_str);
}

// Ensure headers with one cookies are kept the same
TEST(http2_hpack_decoder_decode_header_buffers, header_with_one_cookies)
{
    // arrange
    const uint8_t encoded_headers[] = {
        0x53, 0x01, 0x2a, 
        0x60, 0x07, 'n', '=', 'v', 'a', 'l', 'u', 'e',
    };
    const uint32_t encoded_headers_length {sizeof(encoded_headers)/sizeof(const uint8_t)};
    u8string expected_headers_str = 
        (uint8_t*)  "accept: *\r\n"
                    "cookie: n=value\r\n"
                    "\r\n";
    Field http1_header;
    bool trailers {false};
    // act
    bool success = hpack_decoder->decode_headers((
        const uint8_t*)encoded_headers, encoded_headers_length, start_client_line, trailers);
    hpack_decoder->set_decoded_headers(http1_header);
    // assert
    CHECK(success == true);
    u8string headers_str(http1_header.start(), http1_header.start() + http1_header.length());
    CHECK(expected_headers_str == headers_str);
}

// Ensure headers with one weird cookie and several semicolon is ok
TEST(http2_hpack_decoder_decode_header_buffers, header_with_one_cookies_and_mutiple_semicolon)
{
    // arrange
    const uint8_t encoded_headers[] = {
        0x53, 0x01, 0x2a,
        0x60, 0x07, 'n', '=', ';', ';', ' ', ';', ' '
    };
    const uint32_t encoded_headers_length {sizeof(encoded_headers)/sizeof(const uint8_t)};
    u8string expected_headers_str =
        (uint8_t*)  "accept: *\r\n"
                    "cookie: n=;; ; \r\n"
                    "\r\n";
    Field http1_header;
    bool trailers {false};
    // act
    bool success = hpack_decoder->decode_headers((
        const uint8_t*)encoded_headers, encoded_headers_length, start_client_line, trailers);
    hpack_decoder->set_decoded_headers(http1_header);
    // assert
    CHECK(success == true);
    u8string headers_str(http1_header.start(), http1_header.start() + http1_header.length());
    CHECK(expected_headers_str == headers_str);
}

// Ensure the location of all cookies are concatenated and cookie header is appended at the end of the headers
TEST(http2_hpack_decoder_decode_header_buffers, header_with_cookies_at_middle_and_clutte_all_appended)
{
    // arrange
    const uint8_t encoded_headers[] = {
        0x60, 0x07, 'n', '=', 'v', 'a', 'l', 'u', 'e',
        0x53, 0x01, 0x2a,
        0x60, 0x09, 'n', '2', '=', 'v', 'a', 'l', 'u', 'e', '2',
        0x60, 0x09, 'n', '3', '=', 'v', 'a', 'l', 'u', 'e', '3',
        0x51, 0x8b, 0x2d, 0x4b, 0x70, 0xdd, 0xf4, 0x5a, 0xbe, 0xfb, 0x40, 0x05, 0xdf,
    };
    const uint32_t encoded_headers_length {sizeof(encoded_headers)/sizeof(const uint8_t)};
    u8string expected_headers_str = 
        (uint8_t*)  "accept: *\r\n"
                    "accept-language: en-US,en;q=0.9\r\n"
                    "cookie: n=value; n2=value2; n3=value3\r\n"
                    "\r\n";
    Field http1_header;
    bool trailers {false};
    // act
    bool success = hpack_decoder->decode_headers((
        const uint8_t*)encoded_headers, encoded_headers_length, start_client_line, trailers);
    hpack_decoder->set_decoded_headers(http1_header);
    // assert
    CHECK(success == true);
    u8string headers_str(http1_header.start(), http1_header.start() + http1_header.length());
    CHECK(expected_headers_str == headers_str);
}

// Corner case: Ensure empty headers are kept empty
TEST(http2_hpack_decoder_decode_header_buffers, empty_header)
{
    // arrange
    const uint8_t encoded_headers[0] = {};
    const uint32_t encoded_headers_length {sizeof(encoded_headers)/sizeof(const uint8_t)};
    u8string expected_headers_str = 
        (uint8_t*) "\r\n";
    Field http1_header;
    bool trailers {false};
    // act
    bool success = hpack_decoder->decode_headers((
        const uint8_t*)encoded_headers, encoded_headers_length, start_client_line, trailers);
    hpack_decoder->set_decoded_headers(http1_header);
    // assert
    CHECK(success == true);
    u8string headers_str(http1_header.start(), http1_header.start() + http1_header.length());
    CHECK(expected_headers_str == headers_str);
}

// Ensure that header with cookie 16384 long cookie is processed correctly
TEST(http2_hpack_decoder_decode_header_buffers, header_with_16384_long_cookie)
{
    // arrange
    const uint8_t pre_header[] = {
        0x53, 0x01, 0x2a,
        0x51, 0x8b, 0x2d, 0x4b, 0x70, 0xdd, 0xf4, 0x5a, 0xbe, 0xfb, 0x40, 0x05, 0xdf,
        0x60,                       // 0x60: means cookie header
              0x7f, 0x81, 0x7f,     // the size of the cookie content
    };
    const uint32_t preheader_length = sizeof(pre_header)/sizeof(const uint8_t);
    const uint32_t cookie_value_length = 16384;
    const uint32_t encoded_headers_length {preheader_length + cookie_value_length};
    uint8_t encoded_headers[encoded_headers_length];
    std::copy(std::begin(pre_header), std::end(pre_header), std::begin(encoded_headers));
    encoded_headers[preheader_length] = (const uint8_t)'n';
    encoded_headers[preheader_length+1] = (const uint8_t)'=';
    std::fill(std::begin(encoded_headers)+preheader_length+2, std::end(encoded_headers), (const uint8_t)'.');

    u8string expected_headers_str =
        (uint8_t*)  "accept: *\r\n"
                    "accept-language: en-US,en;q=0.9\r\n"
                    "cookie: n=";
    expected_headers_str += u8string(cookie_value_length-2, (uint8_t)'.') + (uint8_t*)"\r\n\r\n";
    Field http1_header;
    bool trailers {false};
    // act
    bool success = hpack_decoder->decode_headers(
        (const uint8_t*)encoded_headers, encoded_headers_length, start_client_line, trailers);
    hpack_decoder->set_decoded_headers(http1_header);
    // assert
    CHECK(success == true);
    u8string headers_str(http1_header.start(), http1_header.start() + http1_header.length());
    CHECK(expected_headers_str == headers_str);
}

// Ensure that header with cookie 65536 long produces an overflow
TEST(http2_hpack_decoder_decode_header_buffers, header_with_65536_long_cookie_overflow)
{
    // arrange
    const uint8_t pre_header[] = {
        0x53, 0x01, 0x2a,
        0x51, 0x8b, 0x2d, 0x4b, 0x70, 0xdd, 0xf4, 0x5a, 0xbe, 0xfb, 0x40, 0x05, 0xdf,
        0x60,                           // 0x60: means cookie header
              0x7f, 0x81, 0xff, 0x03    // the size of the cookie content
    };
    const uint32_t preheader_length = sizeof(pre_header)/sizeof(const uint8_t);
    const uint32_t cookie_value_length = 65536;
    const uint32_t encoded_headers_length {preheader_length + cookie_value_length};
    uint8_t encoded_headers[encoded_headers_length];
    std::copy(std::begin(pre_header), std::end(pre_header), std::begin(encoded_headers));
    encoded_headers[preheader_length] = (const uint8_t)'n';
    encoded_headers[preheader_length+1] = (const uint8_t)'=';
    std::fill(std::begin(encoded_headers)+preheader_length+2, std::end(encoded_headers), (const uint8_t)'.');

    Field http1_header;
    bool trailers {false};
    // act
    bool success = hpack_decoder->decode_headers(
        (const uint8_t*)encoded_headers, encoded_headers_length, start_client_line, trailers);
    hpack_decoder->set_decoded_headers(http1_header);
    // assert
    CHECK(success == false);
    using hi = Http2Enums::Infraction;
    CHECK(*infractions[HttpCommon::SRC_CLIENT] & hi::INF_DECODED_HEADER_BUFF_OUT_OF_SPACE);
}


int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
