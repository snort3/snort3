//--------------------------------------------------------------------------
// Copyright (C) 2020-2026 Cisco and/or its affiliates. All rights reserved.
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
// pub_sub_http_event_test.cc author Katura Harvey <katharve@cisco.com>

// Unit test for the HttpEvent methods to retrieve HTTP/2 information

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pub_sub/http_events.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_msg_header.h"
#include "service_inspectors/http_inspect/http_msg_section.h"
#include "service_inspectors/http_inspect/http_uri.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

#include <string>
#include <vector>

using namespace snort;
using namespace HttpCommon;

// Stubs to make the code link
Field::Field(int32_t length, const uint8_t* start, bool own_the_buffer_) :
    strt(start), len(length), own_the_buffer(own_the_buffer_)
{}

void Field::set(const Field& input)
{
    strt = input.strt;
    len = input.len;
}

const Field Field::FIELD_NULL { STAT_NO_SOURCE };
const Field& HttpMsgSection::get_classic_buffer(unsigned buffer_type, uint64_t, uint64_t)
{
    mock().actualCall("get_classic_buffer").withParameter("buffer_type", buffer_type);
    Field *out = (Field*)mock().getData("output").getObjectPointer();
    return (*out);
}

bool HttpMsgHeader::has_supported_encoding() const
{
    mock().actualCall("has_supported_encoding");
    return (bool) mock().getData("has_supported_encoding").getIntValue();
}

const Field& HttpMsgHeader::get_true_ip_addr()
{
    Field *out = (Field*)mock().getData("output").getObjectPointer();
    return (*out);
}
int32_t HttpUri::find_host_len(const Field&) { return 0; }

TEST_GROUP(pub_sub_http_event_test)
{
    void setup() override
    {
        mock().setDataObject("output", "Field", nullptr);
    }

    void teardown() override
    {
        mock().checkExpectations();
        mock().clear();
    }
};

TEST(pub_sub_http_event_test, has_supported_encoding_true)
{
    mock().expectOneCall("has_supported_encoding");
    mock().setData("has_supported_encoding", (int)true);
    HttpEvent event(nullptr, false, 0);

    CHECK(event.has_supported_encoding());
}

TEST(pub_sub_http_event_test, has_supported_encoding_false)
{
    mock().expectOneCall("has_supported_encoding");
    mock().setData("has_supported_encoding", (int)false);
    HttpEvent event(nullptr, false, 0);

    CHECK_FALSE(event.has_supported_encoding());
}

TEST(pub_sub_http_event_test, http_traffic)
{
    int64_t stream_id = 0;
    HttpEvent event(nullptr, false, stream_id);
    CHECK_FALSE(event.get_is_httpx());
    CHECK(event.get_httpx_stream_id() == stream_id);
}

TEST(pub_sub_http_event_test, httpx_traffic)
{
    int64_t stream_id = 3;
    HttpEvent event(nullptr, true, stream_id);
    CHECK(event.get_is_httpx());
    CHECK(event.get_httpx_stream_id() == stream_id);
}

TEST(pub_sub_http_event_test, no_true_ip_addr)
{
    const uint8_t* header_start;
    int32_t header_length;
    Field input(0, nullptr);
    mock().setDataObject("output", "Field", &input);
    HttpEvent event(nullptr, false, 0);
    header_start = event.get_trueip_addr(header_length);
    CHECK(header_length == 0);
    CHECK(header_start == nullptr);
}

TEST(pub_sub_http_event_test, true_ip_addr)
{
    const uint8_t* header_start;
    int32_t header_length;
    Field input(7, (const uint8_t*) "1.1.1.1");
    mock().setDataObject("output", "Field", &input);
    HttpEvent event(nullptr, false, 0);
    header_start = event.get_trueip_addr(header_length);
    CHECK(header_length == 7);
    CHECK(memcmp(header_start, "1.1.1.1", 7) == 0);
}

TEST(pub_sub_http_event_test, get_method)
{
    const uint8_t* header_start;
    int32_t header_length;

    mock().expectOneCall("get_classic_buffer").withParameter("buffer_type", HttpEnums::HTTP_BUFFER_METHOD);
    Field input(7, (const uint8_t*) "CONNECT");
    mock().setDataObject("output", "Field", &input);
    HttpEvent event(nullptr, false, 0);
    header_start = event.get_method(header_length);
    CHECK(7 == header_length);
    CHECK(memcmp(header_start, "CONNECT", 7) == 0);
}

TEST(pub_sub_http_event_test, get_response_phrase)
{
    const uint8_t* header_start;
    int32_t header_length;

    mock().expectOneCall("get_classic_buffer").withParameter("buffer_type", HttpEnums::HTTP_BUFFER_STAT_MSG);

    Field input(7, (const uint8_t*) "CONNECT");
    mock().setDataObject("output", "Field", &input);
    HttpEvent event(nullptr, false, 0);
    header_start = event.get_response_phrase(header_length);
    CHECK(7 == header_length);
    CHECK(memcmp(header_start, "CONNECT", 7) == 0);
}

TEST(pub_sub_http_event_test, get_all_raw_headers)
{
    const char* headers = "Content-Type: application/pdf\n"
        "Content-Length: 20000\n";
    int32_t header_length = strlen(headers);
    const uint8_t* header_start;
    int32_t discovered_length;

    mock().expectOneCall("get_classic_buffer").withParameter("buffer_type", HttpEnums::HTTP_BUFFER_RAW_HEADER);
    Field input(header_length, (const uint8_t*) headers);
    mock().setDataObject("output", "Field", &input);
    HttpEvent event(nullptr, false, 0);
    header_start = event.get_all_raw_headers(discovered_length);
    CHECK(discovered_length == header_length);
    CHECK(memcmp(header_start, headers, header_length) == 0);
}

TEST(pub_sub_http_event_test, get_content_length)
{
    const char* content_length = "20000";
    const int32_t content_length_len = strlen(content_length);
    int64_t value = 0;

    mock().expectOneCall("get_classic_buffer").withParameter("buffer_type", HttpEnums::HTTP_BUFFER_HEADER);
    Field input(content_length_len, (const uint8_t*) content_length);
    mock().setDataObject("output", "Field", &input);
    HttpEvent event(nullptr, false, 0);
    ContentLengthStatus status = event.get_content_length(value);
    CHECK_EQUAL(20000, value);
    CHECK(status == ContentLengthStatus::OK);
}

TEST(pub_sub_http_event_test, get_content_length_not_found)
{
    int64_t value = 0;

    mock().expectOneCall("get_classic_buffer").withParameter("buffer_type", HttpEnums::HTTP_BUFFER_HEADER);
    Field input(0, nullptr);
    mock().setDataObject("output", "Field", &input);
    HttpEvent event(nullptr, false, 0);
    ContentLengthStatus status = event.get_content_length(value);
    CHECK(status == ContentLengthStatus::NOT_FOUND);
}

void test_bad_content_length_value(const char* content_length_str)
{
    const int32_t content_length_len = strlen(content_length_str);
    int64_t value = 0;

    mock().expectOneCall("get_classic_buffer").withParameter("buffer_type", HttpEnums::HTTP_BUFFER_HEADER);
    Field input(content_length_len, (const uint8_t*) content_length_str);
    mock().setDataObject("output", "Field", &input);
    HttpEvent event(nullptr, false, 0);
    ContentLengthStatus status = event.get_content_length(value);
    std::string error_msg = "Content length value should be found to be invalid: " + std::string(content_length_str);
    CHECK_TEXT(status == ContentLengthStatus::MALFORMED, error_msg.c_str());
}

void test_valid_content_length(const char* content_length_str, int64_t expected)
{
    const int32_t content_length_len = strlen(content_length_str);
    int64_t value = 0;

    mock().expectOneCall("get_classic_buffer").withParameter("buffer_type", HttpEnums::HTTP_BUFFER_HEADER);
    Field input(content_length_len, (const uint8_t*) content_length_str);
    mock().setDataObject("output", "Field", &input);
    HttpEvent event(nullptr, false, 0);
    ContentLengthStatus status = event.get_content_length(value);
    std::string error_msg = "Content length should be valid: " + std::string(content_length_str);
    CHECK_TEXT(status == ContentLengthStatus::OK, error_msg.c_str());
    CHECK_EQUAL(expected, value);
}

TEST(pub_sub_http_event_test, get_content_length_valid_values)
{
    test_valid_content_length("0", 0);
    test_valid_content_length("007", 7);
    test_valid_content_length("42,42", 42);
    test_valid_content_length("42,99", 42);
    test_valid_content_length("0,0", 0);
    test_valid_content_length("999999999999999999", 999999999999999999LL);
}

TEST(pub_sub_http_event_test, get_content_length_invalid_values)
{
    std::vector<const char*> invalid_content_len_values =
    {
        "12345678901234567890123456789012345678901234567890",
        "9223372036854775807",
        "9223372036854775808",
        "00aA",
        "AC32",
        "-500",
        "+123",
        "12.5",
        ".",
        ",42",
        " ",
        "\t",
    };

    for (const char* content_length_str: invalid_content_len_values)
        test_bad_content_length_value(content_length_str);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

