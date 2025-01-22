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
// extractor_json_logger.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_json_logger.h"

#include <cassert>
#include <string>

#include "utils/util_cstring.h"

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
    std::string s(v, len);

    js.put(f, s);
}

void JsonExtractorLogger::add_field(const char* f, uint64_t v)
{
    js.uput(f, v);
}

void JsonExtractorLogger::add_field(const char* f, struct timeval v)
{
    char u_sec[8];
    snort::SnortSnprintf(u_sec, sizeof(u_sec), ".%06d",(unsigned)v.tv_usec);

    auto str = std::to_string(v.tv_sec) + u_sec;
    js.put(f, str);
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
