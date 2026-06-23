//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// http_cache_data_test.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstring>
#include <vector>

#include "service_inspectors/http_inspect/http_cache_data.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

long HttpTestManager::print_amount {};
bool HttpTestManager::print_hex {};

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

// ---------------------------------------------------------------------------
// append_escaped tests
// ---------------------------------------------------------------------------

TEST_GROUP(append_escaped_test) {};

TEST(append_escaped_test, printable_ascii_unchanged)
{
    std::string out;
    const uint8_t data[] = "GET / HTTP/1.1";
    HttpCacheData::append_escaped(out, data, sizeof(data) - 1, 256);
    CHECK_EQUAL(std::string("GET / HTTP/1.1"), out);
}

TEST(append_escaped_test, nonprintable_byte_escaped)
{
    std::string out;
    const uint8_t data[] = { 0x01 };
    HttpCacheData::append_escaped(out, data, 1, 256);
    CHECK_EQUAL(std::string("\\x01"), out);
    CHECK(out.find('\x01') == std::string::npos);
}

TEST(append_escaped_test, del_byte_escaped)
{
    std::string out;
    const uint8_t data[] = { 0x7F };
    HttpCacheData::append_escaped(out, data, 1, 256);
    CHECK_EQUAL(std::string("\\x7f"), out);
    CHECK(out.find('\x7F') == std::string::npos);
}

TEST(append_escaped_test, backslash_escaped)
{
    std::string out;
    const uint8_t data[] = { '\\' };
    HttpCacheData::append_escaped(out, data, 1, 256);
    CHECK_EQUAL(std::string("\\x5c"), out);
}

TEST(append_escaped_test, crlf_escaped)
{
    std::string out;
    const uint8_t data[] = { '\r', '\n' };
    HttpCacheData::append_escaped(out, data, 2, 256);
    CHECK_EQUAL(std::string("\\x0d\\x0a"), out);
}

TEST(append_escaped_test, stops_at_max_append)
{
    std::string out;
    const uint8_t data[] = "ABCDE";
    HttpCacheData::append_escaped(out, data, 5, 3);
    CHECK_EQUAL(std::string("ABC"), out);
}

TEST(append_escaped_test, backslash_dropped_when_fewer_than_4_remain)
{
    // 2 slots remain (max_append=2); backslash needs 4 → break, 'Z' also not written.
    std::string out;
    const uint8_t data[] = { '\\', 'Z' };
    HttpCacheData::append_escaped(out, data, 2, 2);
    CHECK(out.find("\\x5c") == std::string::npos);
    CHECK(out.find('Z') == std::string::npos);
}

TEST(append_escaped_test, nonprintable_dropped_when_fewer_than_4_remain)
{
    // 3 slots remain; 0x01 needs 4 → break.
    std::string out;
    const uint8_t data[] = { 0x01, 'Z' };
    HttpCacheData::append_escaped(out, data, 2, 3);
    CHECK(out.find("\\x01") == std::string::npos);
    CHECK(out.find('\x01') == std::string::npos);
    CHECK(out.find('Z') == std::string::npos);
}

TEST(append_escaped_test, appends_to_existing_content)
{
    std::string out = "prefix:";
    const uint8_t data[] = "val";
    HttpCacheData::append_escaped(out, data, 3, 256);
    CHECK_EQUAL(std::string("prefix:val"), out);
}

TEST(append_escaped_test, max_append_counts_from_current_length)
{
    // out already has 2 chars, max_append=3 → limit=5 → 3 more chars fit.
    std::string out = "AB";
    const uint8_t data[] = "CDEFG";
    HttpCacheData::append_escaped(out, data, 5, 3);
    CHECK_EQUAL(std::string("ABCDE"), out);
}

// ---------------------------------------------------------------------------
// save_request_line tests
// ---------------------------------------------------------------------------

TEST_GROUP(save_request_line_test)
{
    void teardown() override { reset_cache_data(); }
};

TEST(save_request_line_test, stores_bytes_correctly)
{
    const uint8_t data[] = "GET / HTTP/1.1";
    const uint32_t len = sizeof(data) - 1;
    get_cache_data().request.save_request_line(data, len);
    CHECK_EQUAL(static_cast<uint16_t>(len), get_cache_data().request.request_line_raw_len);
    MEMCMP_EQUAL(get_cache_data().request.request_line_raw.data(), data, len);
}

TEST(save_request_line_test, truncates_at_max_len)
{
    std::vector<uint8_t> long_data(300, 'A');
    get_cache_data().request.save_request_line(long_data.data(), 300);
    CHECK_EQUAL(static_cast<uint16_t>(MAX_REQUEST_LINE_LOG_LEN),
        get_cache_data().request.request_line_raw_len);
}

TEST(save_request_line_test, truncates_at_crlf)
{
    // Content after \r\n (headers) must not be stored.
    const uint8_t data[] = { 'G', 'E', 'T', '\r', '\n', 'X' };
    get_cache_data().request.save_request_line(data, sizeof(data));
    CHECK_EQUAL(static_cast<uint16_t>(3), get_cache_data().request.request_line_raw_len);
    MEMCMP_EQUAL(get_cache_data().request.request_line_raw.data(), "GET", 3);
}

TEST(save_request_line_test, replaces_on_second_call)
{
    const uint8_t first[] = "POST /old HTTP/1.1";
    const uint8_t second[] = "GET /new HTTP/1.1";
    get_cache_data().request.save_request_line(first, sizeof(first) - 1);
    get_cache_data().request.save_request_line(second, sizeof(second) - 1);
    CHECK_EQUAL(static_cast<uint16_t>(sizeof(second) - 1),
        get_cache_data().request.request_line_raw_len);
    MEMCMP_EQUAL(get_cache_data().request.request_line_raw.data(), second, sizeof(second) - 1);
}
