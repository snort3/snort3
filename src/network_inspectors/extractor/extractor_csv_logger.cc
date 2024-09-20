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
// csv_logger.cc author Anna Norokh <anorokh@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_csv_logger.h"

#include <cassert>
#include <string>

#include "utils/util_cstring.h"

static THREAD_LOCAL bool first_write;

void CsvExtractorLogger::add_header()
{
    std::string header;
    char d = '#';

    for (auto n : field_names)
    {
        header += d;
        header += n;
        d = ',';
    }

    header += "\n";

    writer->write(header.c_str());
}

void CsvExtractorLogger::open_record()
{
    first_write = true;
    writer->lock();
}

void CsvExtractorLogger::close_record()
{
    writer->write("\n");
    writer->unlock();
}

void CsvExtractorLogger::add_field(const char*, const char* v)
{
    first_write ? []() { first_write = false; } () : writer->write(",");
    writer->write(v);
}

void CsvExtractorLogger::add_field(const char*, const char* v, size_t len)
{
    first_write ? []() { first_write = false; } () : writer->write(",");
    writer->write(v, len);
}

void CsvExtractorLogger::add_field(const char*, uint64_t v)
{
    first_write ? []() { first_write = false; } () : writer->write(",");
    writer->write(v);
}

void CsvExtractorLogger::add_field(const char*, struct timeval v)
{
    first_write ? []() { first_write = false; } () : writer->write(",");

    char u_sec[8];
    snort::SnortSnprintf(u_sec, sizeof(u_sec), ".%06d", (unsigned)v.tv_usec);

    writer->write(v.tv_sec);
    writer->write(u_sec);
}

void CsvExtractorLogger::add_field(const char*, const snort::SfIp& v)
{
    first_write ? []() { first_write = false; } () : writer->write(",");

    snort::SfIpString buf;

    v.ntop(buf);
    writer->write(buf);
}

CsvExtractorLogger::~CsvExtractorLogger()
{
    delete writer;
}
