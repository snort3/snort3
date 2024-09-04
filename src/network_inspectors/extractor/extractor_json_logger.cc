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
// json_logger.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "extractor_json_logger.h"

#include <cassert>

void JsonExtractorLogger::open_record()
{
    oss.str("");
    js.open();
}

void JsonExtractorLogger::close_record()
{
    js.close();

    writer->lock();
    writer->write(oss.str().c_str());
    writer->unlock();
}

void JsonExtractorLogger::add_field(const char* f, const snort::Value& v)
{
    switch (v.get_type())
    {
    case snort::Value::ValueType::VT_UNUM:
        js.uput(f, v.get_uint64());
        break;

    case snort::Value::ValueType::VT_STR:
        js.put(f, v.get_string());
        break;

    case snort::Value::ValueType::VT_BOOL: // fallthrough
    case snort::Value::ValueType::VT_NUM:  // fallthrough
    case snort::Value::ValueType::VT_REAL: // fallthrough
    default:
        assert(false);
        break;
    }
}
