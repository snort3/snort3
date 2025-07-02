//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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
// extractor_json_logger.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_json_logger.h"

#include <cassert>
#include <string>

#include "helpers/json_stream.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

void JsonExtractorLogger::write_key(const char* key)
{
    if (!first_field_written)
        first_field_written = true;
    else
        out_buffer += ", ";

    out_buffer += '"';

    if (key)
        out_buffer += key;

    out_buffer += "\": ";
}

JsonExtractorLogger::JsonExtractorLogger(snort::Connector* conn, TimeType ts_type)
    : ExtractorLogger(conn), first_field_written(false)
{
    switch (ts_type)
    {
    case TimeType::SNORT:
        add_ts = &JsonExtractorLogger::ts_snort;
        break;
    case TimeType::SNORT_YY:
        add_ts = &JsonExtractorLogger::ts_snort_yy;
        break;
    case TimeType::UNIX:
        add_ts = &JsonExtractorLogger::ts_unix;
        break;
    case TimeType::UNIX_S:
        add_ts = &JsonExtractorLogger::ts_sec;
        break;
    case TimeType::UNIX_US:
        add_ts = &JsonExtractorLogger::ts_usec;
        break;
    case TimeType::MAX: // fallthrough
    default:
        add_ts = &JsonExtractorLogger::ts_snort;
        break;
    }
}

void JsonExtractorLogger::open_record()
{
    out_buffer.clear();
    out_buffer += "{ ";
    first_field_written = false;
}

void JsonExtractorLogger::close_record(const snort::Connector::ID& service_id)
{
    out_buffer += " }";

    snort::ConnectorMsg cmsg(reinterpret_cast<const uint8_t*>(out_buffer.c_str()),
        out_buffer.length(), false);

    output_conn->transmit_message(cmsg, service_id);
}

void JsonExtractorLogger::add_field(const char* f, const char* v)
{
    if (!v or v[0] == '\0')
        return;

    write_key(f);
    out_buffer += '"';
    escape_json_append(out_buffer, v, std::strlen(v));
    out_buffer += '"';
}

void JsonExtractorLogger::add_field(const char* f, const char* v, size_t len)
{
    if (!v or v[0] == '\0' or len == 0)
        return;

    write_key(f);
    out_buffer += '"';
    escape_json_append(out_buffer, v, len);
    out_buffer += '"';
}

void JsonExtractorLogger::add_field(const char* f, uint64_t v)
{
    write_key(f);
    out_buffer += std::to_string(v);
}

void JsonExtractorLogger::add_field(const char* f, const snort::SfIp& v)
{
    snort::SfIpString buf;

    v.ntop(buf);

    if (buf[0] == '\0')
        return;

    write_key(f);
    out_buffer += '"';
    out_buffer += buf;
    out_buffer += '"';
}

void JsonExtractorLogger::add_field(const char* f, bool v)
{
    write_key(f);
    out_buffer += (v ? "true" : "false");
}

void JsonExtractorLogger::add_field(const char* f, struct timeval v)
{
    (this->*add_ts)(f, v);
}

void JsonExtractorLogger::ts_snort(const char* f, const struct timeval& v)
{
    char ts[TIMEBUF_SIZE];
    snort::ts_print(&v, ts, false);

    write_key(f);
    out_buffer += '"';
    out_buffer += ts;
    out_buffer += '"';
}

void JsonExtractorLogger::ts_snort_yy(const char* f, const struct timeval& v)
{
    char ts[TIMEBUF_SIZE];
    snort::ts_print(&v, ts, true);

    write_key(f);
    out_buffer += '"';
    out_buffer += ts;
    out_buffer += '"';
}

void JsonExtractorLogger::ts_unix(const char* f, const struct timeval& v)
{
    double sec = static_cast<double>(v.tv_sec);
    double usec = static_cast<double>(v.tv_usec);
    double val = sec + usec / 1000000.0;

    const unsigned precision = 6;
    const unsigned buf_size = 20 + 1 + precision + 1;

    char buf[buf_size];
    std::snprintf(buf, sizeof(buf), "%.*f", precision, val);

    write_key(f);
    out_buffer += buf;
}

void JsonExtractorLogger::ts_sec(const char* f, const struct timeval& v)
{
    uint64_t sec = static_cast<uint64_t>(v.tv_sec);

    write_key(f);
    out_buffer += std::to_string(sec);
}

void JsonExtractorLogger::ts_usec(const char* f, const struct timeval& v)
{
    uint64_t sec = static_cast<uint64_t>(v.tv_sec);
    uint64_t usec = static_cast<uint64_t>(v.tv_usec);

    write_key(f);
    out_buffer += std::to_string(sec * 1000000 + usec);
}

void JsonExtractorLogger::add_field(const char* f, const std::vector<const char*>& v)
{
    if (v.empty())
        return;

    write_key(f);
    out_buffer += "[ ";

    auto it = v.cbegin();

    out_buffer += '"';
    escape_json_append(out_buffer, *it, std::strlen(*it));
    out_buffer += '"';

    for (++it; it != v.cend(); ++it)
    {
        out_buffer += ", \"";
        escape_json_append(out_buffer, *it, std::strlen(*it));
        out_buffer += '"';
    }
    out_buffer += " ]";
}

void JsonExtractorLogger::add_field(const char* f, const std::vector<uint64_t>& v)
{
    if (v.empty())
        return;

    write_key(f);
    out_buffer += "[ ";

    auto it = v.cbegin();
    out_buffer += std::to_string(*it);

    for (++it; it != v.cend(); ++it)
    {
        out_buffer += ", ";
        out_buffer += std::to_string(*it);
    }

    out_buffer += " ]";
}

void JsonExtractorLogger::add_field(const char* f, const std::vector<bool>& v)
{
    if (v.empty())
        return;

    write_key(f);
    out_buffer += "[ ";

    auto it = v.cbegin();
    out_buffer += (*it ? "true" : "false");

    for (++it; it != v.cend(); ++it)
        out_buffer += (*it ? ", true" : ", false");

    out_buffer += " ]";
}

#ifdef UNIT_TEST

#include <vector>

#include "catch/snort_catch.h"

#include "extractor_null_conn.h"

class JsonExtractorLoggerTest : public JsonExtractorLogger
{
public:
    JsonExtractorLoggerTest() : JsonExtractorLogger(new ExtractorNullConnector, TimeType::MAX) { }

    ~JsonExtractorLoggerTest() override
    { delete output_conn; }

    void check(const char* f, const std::vector<bool>& v, const std::string& expected)
    {
        add_field(f, v);
        CHECK(out_buffer == expected);
        out_buffer.clear();
    }

    void check(const char* f, const std::vector<uint64_t>& v, const std::string& expected)
    {
        add_field(f, v);
        CHECK(out_buffer == expected);
        out_buffer.clear();
    }

    void check(const char* f, const std::vector<const char*>& v, const std::string& expected)
    {
        add_field(f, v);
        CHECK(out_buffer == expected);
        out_buffer.clear();
    }
};

TEST_CASE_METHOD(JsonExtractorLoggerTest, "json vector bool: empty", "[extractor]")
{
    const std::vector<bool> bool_vec = { };
    check("bool", bool_vec, "");
}

TEST_CASE_METHOD(JsonExtractorLoggerTest, "json vector bool: 3 items", "[extractor]")
{
    const std::vector<bool> bool_vec = { true, false, true };
    check("bool", bool_vec, "\"bool\": [ true, false, true ]");
}

TEST_CASE_METHOD(JsonExtractorLoggerTest, "json vector uint64_t: empty", "[extractor]")
{
    const std::vector<uint64_t> num_vec = { };
    check("num", num_vec, "");
}

TEST_CASE_METHOD(JsonExtractorLoggerTest, "json vector uint64_t: 3 items", "[extractor]")
{
    const std::vector<uint64_t> num_vec = { 1,2,3 };
    check("num", num_vec, "\"num\": [ 1, 2, 3 ]");
}

TEST_CASE_METHOD(JsonExtractorLoggerTest, "json vector str: empty", "[extractor]")
{
    const std::vector<const char*> char_vec = { };
    check("str", char_vec, "");
}

TEST_CASE_METHOD(JsonExtractorLoggerTest, "json vector str: 3 items", "[extractor]")
{
    const std::vector<const char*> num_vec = { "exe", "pdf", "txt" };
    check("str", num_vec, "\"str\": [ \"exe\", \"pdf\", \"txt\" ]");
}

TEST_CASE_METHOD(JsonExtractorLoggerTest, "json multiple fields", "[extractor]")
{
    add_field("1", "foo");
    add_field("2", "bar", 3);
    add_field("3", (uint64_t)123);
    add_field("4", true);
    add_field("5", false);

    snort::SfIp ip;
    ip.pton(AF_INET, "1.1.1.1");
    add_field("6", ip);

    CHECK(out_buffer == "\"1\": \"foo\", \"2\": \"bar\", \"3\": 123, "
        "\"4\": true, \"5\": false, \"6\": \"1.1.1.1\"");
    out_buffer.clear();
}

TEST_CASE_METHOD(JsonExtractorLoggerTest, "json field with empty and null values", "[extractor]")
{
    add_field("1", "foo");
    add_field("2", nullptr);
    add_field("3", "");
    add_field("4", "bar");
    CHECK(out_buffer == "\"1\": \"foo\", \"4\": \"bar\"");
}

TEST_CASE_METHOD(JsonExtractorLoggerTest, "json field with empty and null values with length", "[extractor]")
{
    add_field("1", "foo", 3);
    add_field("2", nullptr, 5);
    add_field("3", "");
    add_field("4", "not empty", 0);
    add_field("5", "bar", 3);
    CHECK(out_buffer == "\"1\": \"foo\", \"5\": \"bar\"");
}

TEST_CASE_METHOD(JsonExtractorLoggerTest, "json field bad ip", "[extractor]")
{
    snort::SfIp ip;
    ip.pton(AF_INET, "10.10.10.10");
    add_field("ipv4", ip);
    ip = { };

    ip.pton(AF_INET, "bad ip");
    add_field("bad_ip", ip);
    ip = { };

    ip.pton(AF_INET6, "2001:db8:85a3::8a2e:370:7334");
    add_field("ipv6", ip);

    CHECK(out_buffer == "\"ipv4\": \"10.10.10.10\", "
        "\"ipv6\": \"2001:0db8:85a3:0000:0000:8a2e:0370:7334\"");
}

TEST_CASE_METHOD(JsonExtractorLoggerTest, "json open/close record", "[extractor]")
{
    open_record();
    close_record(snort::Connector::ID(1));
    CHECK(out_buffer == "{  }");
}

#endif

