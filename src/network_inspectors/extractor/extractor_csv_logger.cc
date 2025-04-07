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
// extractor_csv_logger.cc author Cisco

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

CsvExtractorLogger::CsvExtractorLogger(snort::Connector* conn, TimeType ts_type, char delim)
    : ExtractorLogger(conn), delimiter(delim)
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
        d = delimiter;
    }

    ConnectorMsg cmsg((const uint8_t*)header.c_str(), header.size(), false);
    output_conn->transmit_message(cmsg, service_id);
}

void CsvExtractorLogger::open_record()
{
    record.clear();
}

void CsvExtractorLogger::close_record(const Connector::ID& service_id)
{
    if (record.empty())
        return;

    auto data = (const uint8_t*)record.data() + 1;
    auto size = record.size() - 1;
    ConnectorMsg cmsg(data, size, false);

    output_conn->transmit_message(cmsg, service_id);
}

void CsvExtractorLogger::add_field(const char*, const char* v)
{
    record.push_back(delimiter);
    add_escaped(v, strlen(v));
}

void CsvExtractorLogger::add_field(const char*, const char* v, size_t len)
{
    record.push_back(delimiter);
    add_escaped(v, len);
}

void CsvExtractorLogger::add_field(const char*, uint64_t v)
{
    record.push_back(delimiter);
    record.append(to_string(v));
}

void CsvExtractorLogger::add_field(const char*, const snort::SfIp& v)
{
    record.push_back(delimiter);

    snort::SfIpString buf;

    v.ntop(buf);
    record.append(buf);
}

void CsvExtractorLogger::add_field(const char*, bool v)
{
    record.push_back(delimiter);

    record.append(v ? "true" : "false");
}

static void escape_csv_style(string& record, const char* v, size_t len, char delimiter)
{
    assert(v);
    assert(len);

    constexpr float escape_resize_factor = 1.2;
    const char* p = v;
    const char* end = v + len;

    record.reserve(record.length() + len * escape_resize_factor);

    bool to_quote = false;
    std::vector<ptrdiff_t> quote_positions;

    while (p < end)
    {
        if (*p == '"')
        {
            to_quote = true;
            quote_positions.push_back(p - v);
        }

        to_quote = to_quote or *p == delimiter or !isprint(*p) or (isblank(*p) and (p == v or p == end - 1));

        ++p;
    }

    if (!to_quote)
    {
        record.append(v, len);
        return;
    }

    record.push_back('"');

    ptrdiff_t curr_pos = 0;
    for (ptrdiff_t quote_pos : quote_positions)
    {
        assert(quote_pos >= curr_pos);
        record.append(v + curr_pos, quote_pos - curr_pos);
        record.push_back('"');
        curr_pos = quote_pos;
    }

    record.append(v + curr_pos, len - curr_pos);
    record.push_back('"');
}

static void escape_tsv_style(string& record, const char* v, size_t len, char delimiter)
{
    assert(v);
    assert(len);

    const char* p = v - 1;
    const char* end = v + len;
    bool clean = true;

    while (++p < end and clean)
        clean = !(*p == delimiter or *p == '\r' or *p == '\n' or *p == '\\');

    if (clean)
    {
        record.append(v, len);
        return;
    }

    p = v - 1;
    end = v + len;

    while (++p < end)
    {
        if (*p == '\t')
            record.append("\\t");
        else if (*p == '\r')
            record.append("\\r");
        else if (*p == '\n')
            record.append("\\n");
        else if (*p == '\\')
            record.append("\\\\");
        else
            record.push_back(*p);

        assert(delimiter == '\t');
    }
}

void CsvExtractorLogger::add_escaped(const char* v, size_t len)
{
    bool visible = isprint(delimiter);

    if (!v || len == 0)
    {
        if (!visible)
            record.append("-");
        return;
    }

    return visible
        ? escape_csv_style(record, v, len, delimiter)
        : escape_tsv_style(record, v, len, delimiter);
}

void CsvExtractorLogger::add_field(const char*, struct timeval v)
{
    record.push_back(delimiter);
    (this->*add_ts)(v);
}

void CsvExtractorLogger::ts_snort(const struct timeval& v)
{
    char ts[TIMEBUF_SIZE];
    ts_print(&v, ts, false);

    record.append(ts);
}

void CsvExtractorLogger::ts_snort_yy(const struct timeval& v)
{
    char ts[TIMEBUF_SIZE];
    ts_print(&v, ts, true);

    record.append(ts);
}

void CsvExtractorLogger::ts_unix(const struct timeval& v)
{
    char ts[numeric_limits<uint64_t>::digits10 + 8];

    snort::SnortSnprintf(ts, sizeof(ts), "%" PRIu64 ".%06d", (uint64_t)v.tv_sec, (unsigned)v.tv_usec);
    record.append(ts);
}

void CsvExtractorLogger::ts_sec(const struct timeval& v)
{
    uint64_t sec = (uint64_t)v.tv_sec;

    record.append(to_string(sec));
}

void CsvExtractorLogger::ts_usec(const struct timeval& v)
{
    uint64_t sec = (uint64_t)v.tv_sec;
    uint64_t usec = (uint64_t)v.tv_usec;

    record.append(to_string(sec * 1000000 + usec));
}

#ifdef UNIT_TEST

#include "catch/snort_catch.h"

class CsvExtractorLoggerHelper : public CsvExtractorLogger
{
public:
    CsvExtractorLoggerHelper(char separator) : CsvExtractorLogger(nullptr, TimeType::MAX, separator) {}

    void check(const char* input, size_t i_len, const std::string& expected)
    {
        record.clear();
        add_escaped(input, i_len);
        CHECK(record == expected);
    }
};

class CsvExtractorLoggerTest
{
public:

    void check_csv(const char* input, size_t i_len, const std::string& expected)
    { csv.check(input, i_len, expected); }

    void check_tsv(const char* input, size_t i_len, const std::string& expected)
    { tsv.check(input, i_len, expected); }

private:
    CsvExtractorLoggerHelper csv{','};
    CsvExtractorLoggerHelper tsv{'\t'};
};

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: nullptr", "[extractor]")
{
    check_csv(nullptr, 1, "");
    check_tsv(nullptr, 1, "-");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: zero len", "[extractor]")
{
    const char* input = "";
    check_csv(input, 0, "");
    check_tsv(input, 0, "-");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: no special chars", "[extractor]")
{
    const char* input = "simple_text";
    check_csv(input, strlen(input), "simple_text");
    check_tsv(input, strlen(input), "simple_text");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: comma", "[extractor]")
{
    const char* input = "text,with,commas";
    check_csv(input, strlen(input), "\"text,with,commas\"");
    check_tsv(input, strlen(input), "text,with,commas");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: tab", "[extractor]")
{
    const char* input = "text\t with\t tabs";
    check_csv(input, strlen(input), "\"text\t with\t tabs\"");
    check_tsv(input, strlen(input), "text\\t with\\t tabs");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: newline", "[extractor]")
{
    const char* input = "text\n with\n newlines";
    check_csv(input, strlen(input), "\"text\n with\n newlines\"");
    check_tsv(input, strlen(input), "text\\n with\\n newlines");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: CR", "[extractor]")
{
    const char* input = "text\r with\r returns";
    check_csv(input, strlen(input), "\"text\r with\r returns\"");
    check_tsv(input, strlen(input), "text\\r with\\r returns");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: whitespaces", "[extractor]")
{
    const char* input = "text with ws";
    check_csv(input, strlen(input), "text with ws");
    check_tsv(input, strlen(input), "text with ws");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: whitespace at the beginning", "[extractor]")
{
    const char* input = " start_with_ws";
    check_csv(input, strlen(input), "\" start_with_ws\"");
    check_tsv(input, strlen(input), " start_with_ws");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: whitespace at the end", "[extractor]")
{
    const char* input = "end_with_ws ";
    check_csv(input, strlen(input), "\"end_with_ws \"");
    check_tsv(input, strlen(input), "end_with_ws ");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: quotes", "[extractor]")
{
    const char* input = "text\"with\"quotes";
    check_csv(input, strlen(input), "\"text\"\"with\"\"quotes\"");
    check_tsv(input, strlen(input), "text\"with\"quotes");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: mixed", "[extractor]")
{
    const char* input = "text,with\n mixed\"chars\r";
    check_csv(input, strlen(input), "\"text,with\n mixed\"\"chars\r\"");
    check_tsv(input, strlen(input), "text,with\\n mixed\"chars\\r");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: single quote", "[extractor]")
{
    const char* input = "\"";
    check_csv(input, strlen(input), "\"\"\"\"");
    check_tsv(input, strlen(input), "\"");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: single comma", "[extractor]")
{
    const char* input = ",";
    check_csv(input, strlen(input), "\",\"");
    check_tsv(input, strlen(input), ",");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: single tab", "[extractor]")
{
    const char* input = "\t";
    check_csv(input, strlen(input), "\"\t\"");
    check_tsv(input, strlen(input), "\\t");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: single newline", "[extractor]")
{
    const char* input = "\n";
    check_csv(input, strlen(input), "\"\n\"");
    check_tsv(input, strlen(input), "\\n");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: single CR", "[extractor]")
{
    const char* input = "\r";
    check_csv(input, strlen(input), "\"\r\"");
    check_tsv(input, strlen(input), "\\r");
}

TEST_CASE_METHOD(CsvExtractorLoggerTest, "escape: single whitespace", "[extractor]")
{
    const char* input = " ";
    check_csv(input, strlen(input), "\" \"");
    check_tsv(input, strlen(input), " ");
}

#endif
