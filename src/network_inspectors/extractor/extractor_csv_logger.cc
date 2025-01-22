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
// extractor_csv_logger.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_csv_logger.h"

#include <cassert>
#include <limits>
#include <string>

#include "utils/util_cstring.h"

using namespace snort;
using namespace std;

static THREAD_LOCAL bool first_write;

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
    buffer.append(v);
}

void CsvExtractorLogger::add_field(const char*, const char* v, size_t len)
{
    first_write ? []() { first_write = false; } () : buffer.push_back(',');
    buffer.append(v, len);
}

void CsvExtractorLogger::add_field(const char*, uint64_t v)
{
    first_write ? []() { first_write = false; } () : buffer.push_back(',');
    buffer.append(to_string(v));
}

void CsvExtractorLogger::add_field(const char*, struct timeval v)
{
    first_write ? []() { first_write = false; } () : buffer.push_back(',');

    char time_str[numeric_limits<uint64_t>::digits10 + 8];
    snort::SnortSnprintf(time_str, sizeof(time_str), "%" PRIu64 ".%06d", (uint64_t)v.tv_sec, (unsigned)v.tv_usec);

    buffer.append(time_str);
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

