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

#include "utils/util.h"
#include "utils/util_cstring.h"

JsonExtractorLogger::JsonExtractorLogger(snort::Connector* conn, TimeType ts_type)
    : ExtractorLogger(conn), oss(), js(oss)
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
    oss.str("");
    js.open();
}

void JsonExtractorLogger::close_record(const snort::Connector::ID& service_id)
{
    js.close();

    // FIXIT-L: we're removing last character(\n) due to a limitation of
    // Json Stream configuration
    assert(oss.str()[oss.str().size() - 1] == '\n');

    output_conn->transmit_message(snort::ConnectorMsg(
        (const uint8_t*)oss.str().c_str(), oss.str().size() - 1, false), service_id);
}

void JsonExtractorLogger::add_field(const char* f, const char* v)
{
    js.put(f, v);
}

void JsonExtractorLogger::add_field(const char* f, const char* v, size_t len)
{
    js.put(f, {v, len});
}

void JsonExtractorLogger::add_field(const char* f, uint64_t v)
{
    js.uput(f, v);
}

void JsonExtractorLogger::add_field(const char* f, const snort::SfIp& v)
{
    snort::SfIpString buf;

    v.ntop(buf);
    js.put(f, buf);
}

void JsonExtractorLogger::add_field(const char* f, bool v)
{
    v ? js.put_true(f) : js.put_false(f);
}

void JsonExtractorLogger::add_field(const char* f, struct timeval v)
{
    (this->*add_ts)(f, v);
}

void JsonExtractorLogger::ts_snort(const char* f, const struct timeval& v)
{
    char ts[TIMEBUF_SIZE];
    snort::ts_print(&v, ts, false);

    js.put(f, ts);
}

void JsonExtractorLogger::ts_snort_yy(const char* f, const struct timeval& v)
{
    char ts[TIMEBUF_SIZE];
    snort::ts_print(&v, ts, true);

    js.put(f, ts);
}

void JsonExtractorLogger::ts_unix(const char* f, const struct timeval& v)
{
   double sec = (uint64_t)v.tv_sec;
   double usec = (uint64_t)v.tv_usec;

   js.put(f, sec + usec / 1000000.0, 6);
}

void JsonExtractorLogger::ts_sec(const char* f, const struct timeval& v)
{
   uint64_t sec = (uint64_t)v.tv_sec;

   js.uput(f, sec);
}

void JsonExtractorLogger::ts_usec(const char* f, const struct timeval& v)
{
   uint64_t sec = (uint64_t)v.tv_sec;
   uint64_t usec = (uint64_t)v.tv_usec;

   js.uput(f, sec * 1000000 + usec);
}
