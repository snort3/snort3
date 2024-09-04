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

static THREAD_LOCAL bool first_write;

void CsvExtractorLogger::add_header()
{
    std::string header;

    header += "#";
    header += fields_name[0];
    for (size_t i = 1; i < fields_name.size(); ++i)
    {
        header += ",";
        header += fields_name[i];
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

void CsvExtractorLogger::add_field(const char*, const snort::Value& v)
{
    switch (v.get_type())
    {
    case snort::Value::ValueType::VT_UNUM:
    {
        first_write ? []() { first_write = false; } () : writer->write(",");
        writer->write(std::to_string(v.get_uint64()).c_str());
        break;
    }

    case snort::Value::ValueType::VT_STR:
    {
        first_write ? []() { first_write = false; } () : writer->write(",");
        writer->write(v.get_string());
        break;
    }

    case snort::Value::ValueType::VT_BOOL: // fallthrough
    case snort::Value::ValueType::VT_NUM:  // fallthrough
    case snort::Value::ValueType::VT_REAL: // fallthrough
    default:
        assert(false);
        break;
    }
}

CsvExtractorLogger::~CsvExtractorLogger()
{
    delete writer;
}
