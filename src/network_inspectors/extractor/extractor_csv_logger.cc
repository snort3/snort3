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
// extractor_csv_logger.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_csv_logger.h"

#include <cassert>
#include <cctype>
#include <cstddef>
#include <limits>
#include <string>

#include "utils/util.h"
#include "utils/util_cstring.h"

using namespace snort;
using namespace std;

static THREAD_LOCAL bool first_write;

CsvExtractorLogger::CsvExtractorLogger(snort::Connector* conn, TimeType ts_type)
    : ExtractorLogger(conn)
{
    switch (ts_type)
    {
    case TimeType::SNORT:
        add_ts = &CsvExtractorLogger::ts_snort;
        break;
    case TimeType::SNORT_YY:
        add_ts = &CsvExtractorLogger::ts_snort_yy;
        break;
    case TimeType::UNIX:
        add_ts = &CsvExtractorLogger::ts_unix;
        break;
    case TimeType::UNIX_S:
        add_ts = &CsvExtractorLogger::ts_sec;
        break;
    case TimeType::UNIX_US:
        add_ts = &CsvExtractorLogger::ts_usec;
        break;
    case TimeType::MAX: // fallthrough
    default:
        add_ts = &CsvExtractorLogger::ts_snort;
        break;
    }
}

void CsvExtractorLogger::add_header(const vector<const char*>& field_names, const Connector::ID& service_id)
{
    string header;
    char d = '#';

    for (auto n : field_names)
    {
        header += d;
        header += n;
        d = ',';
    }

    ConnectorMsg cmsg((const uint8_t*)header.c_str(), header.size(), false);
    output_conn->transmit_message(cmsg, service_id);
}

void CsvExtractorLogger::open_record()
{
    first_write = true;
}

void CsvExtractorLogger::close_record(const Connector::ID& service_id)
{
    ConnectorMsg cmsg((const uint8_t*)buffer.c_str(), buffer.size(), false);
    output_conn->transmit_message(cmsg, service_id);

    buffer.clear();
}

void CsvExtractorLogger::add_field(const char*, const char* v)
{
    first_write ? []() { first_write = false; } () : buffer.push_back(',');
    add_escaped(v, strlen(v));
}

void CsvExtractorLogger::add_field(const char*, const char* v, size_t len)
{
    first_write ? []() { first_write = false; } () : buffer.push_back(',');
    add_escaped(v, len);
}

void CsvExtractorLogger::add_field(const char*, uint64_t v)
{
    first_write ? []() { first_write = false; } () : buffer.push_back(',');
    buffer.append(to_string(v));
}

void CsvExtractorLogger::add_field(const char*, const snort::SfIp& v)
{
    first_write ? []() { first_write = false; } () : buffer.push_back(',');

    snort::SfIpString buf;

    v.ntop(buf);
    buffer.append(buf);
}

void CsvExtractorLogger::add_field(const char*, bool v)
{
    first_write ? []() { first_write = false; } () : buffer.push_back(',');

    buffer.append(v ? "true" : "false");
}

void CsvExtractorLogger::add_escaped(const char* v, size_t len)
{
    if (!v || len == 0)
        return;

    constexpr float escape_resize_factor = 1.2;

    const char* p = v;
    const char* end = v + len;

    buffer.reserve(buffer.length() + len * escape_resize_factor);

    bool to_quote = false;
    std::vector<ptrdiff_t> quote_positions;

    while (p < end)
    {
        if (*p == '"')
        {
            to_quote = true;
            quote_positions.push_back(p - v);
        }

        to_quote = to_quote or *p == ',' or !isprint(*p) or (isblank(*p) and (p == v or p == end - 1));

        ++p;
    }

    if (!to_quote)
    {
        buffer.append(v, len);
        return;
    }

    buffer.push_back('"');

    ptrdiff_t curr_pos = 0;
    for (ptrdiff_t quote_pos : quote_positions)
    {
        assert(quote_pos >= curr_pos);
        buffer.append(v + curr_pos, quote_pos - curr_pos);
        buffer.push_back('"');
        curr_pos = quote_pos;
    }

    buffer.append(v + curr_pos, len - curr_pos);
    buffer.push_back('"');
}

void CsvExtractorLogger::add_field(const char*, struct timeval v)
{
    first_write ? []() { first_write = false; } () : buffer.push_back(',');
    (this->*add_ts)(v);
}

void CsvExtractorLogger::ts_snort(const struct timeval& v)
{
    char ts[TIMEBUF_SIZE];
    ts_print(&v, ts, false);

    buffer.append(ts);
}

void CsvExtractorLogger::ts_snort_yy(const struct timeval& v)
{
    char ts[TIMEBUF_SIZE];
    ts_print(&v, ts, true);

    buffer.append(ts);
}

void CsvExtractorLogger::ts_unix(const struct timeval& v)
{
    char ts[numeric_limits<uint64_t>::digits10 + 8];

    snort::SnortSnprintf(ts, sizeof(ts), "%" PRIu64 ".%06d", (uint64_t)v.tv_sec, (unsigned)v.tv_usec);
    buffer.append(ts);
}

void CsvExtractorLogger::ts_sec(const struct timeval& v)
{
    uint64_t sec = (uint64_t)v.tv_sec;

    buffer.append(to_string(sec));
}

void CsvExtractorLogger::ts_usec(const struct timeval& v)
{
    uint64_t sec = (uint64_t)v.tv_sec;
    uint64_t usec = (uint64_t)v.tv_usec;

    buffer.append(to_string(sec * 1000000 + usec));
}

#ifdef UNIT_TEST

#include "catch/snort_catch.h"

class CsvExtractorLoggerTest : public CsvExtractorLogger
{
public:
    CsvExtractorLoggerTest() : CsvExtractorLogger(nullptr, TimeType::MAX) {}

    void check_escaping(const char* input, size_t i_len, const std::string& expected)
    {
        buffer.clear();
        add_escaped(input, i_len);
        CHECK(buffer == expected);
    }
};

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: nullptr", "[extractor]")
{
    check_escaping(nullptr, 1, "");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: zero len", "[extractor]")
{
    const char* input = "";
    check_escaping(input, 0, "");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: no special chars", "[extractor]")
{
    const char* input = "simple_text";
    check_escaping(input, strlen(input), "simple_text");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: comma", "[extractor]")
{
    const char* input = "text,with,commas";
    check_escaping(input, strlen(input), "\"text,with,commas\"");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: newline", "[extractor]")
{
    const char* input = "text\nwith\nnewlines";
    check_escaping(input, strlen(input), "\"text\nwith\nnewlines\"");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: CR", "[extractor]")
{
    const char* input = "text\rwith\rreturns";
    check_escaping(input, strlen(input), "\"text\rwith\rreturns\"");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: whitespaces", "[extractor]")
{
    const char* input = "text with ws";
    check_escaping(input, strlen(input), "text with ws");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: whitespace at the beginning", "[extractor]")
{
    const char* input = " start_with_ws";
    check_escaping(input, strlen(input), "\" start_with_ws\"");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: whitespace at the end", "[extractor]")
{
    const char* input = "end_with_ws ";
    check_escaping(input, strlen(input), "\"end_with_ws \"");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: quotes", "[extractor]")
{
    const char* input = "text\"with\"quotes";
    check_escaping(input, strlen(input), "\"text\"\"with\"\"quotes\"");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: mixed", "[extractor]")
{
    const char* input = "text,with\nmixed\"chars\r";
    check_escaping(input, strlen(input), "\"text,with\nmixed\"\"chars\r\"");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: single quote", "[extractor]")
{
    const char* input = "\"";
    check_escaping(input, strlen(input), "\"\"\"\"");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: single comma", "[extractor]")
{
    const char* input = ",";
    check_escaping(input, strlen(input), "\",\"");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: single newline", "[extractor]")
{
    const char* input = "\n";
    check_escaping(input, strlen(input), "\"\n\"");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: single CR", "[extractor]")
{
    const char* input = "\r";
    check_escaping(input, strlen(input), "\"\r\"");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: single whitespace", "[extractor]")
{
    const char* input = " ";
    check_escaping(input, strlen(input), "\" \"");
}

#endif
