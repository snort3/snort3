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
// extractor_logger.h author Anna Norokh <anorokh@cisco.com>

#ifndef EXTRACTOR_LOGGER_H
#define EXTRACTOR_LOGGER_H

#include <string>
#include <vector>

#include "framework/value.h"

#include "extractor_writer.h"

class FormatType
{
public:
    enum Value : uint8_t
    {
        CSV,
        JSON,
        MAX
    };

    FormatType() = default;
    constexpr FormatType(Value a) : v(a) {}
    template<typename T> constexpr FormatType(T a) : v((Value)a) {}

    constexpr operator Value() const { return v; }
    explicit operator bool() const = delete;

    const char* c_str() const
    {
        switch (v)
        {
        case CSV:
            return "csv";
        case JSON:
            return "json";
        case MAX: // fallthrough
        default:
            return "(not set)";
        }
    }

private:
    Value v = CSV;
};

class ExtractorLogger
{
public:
    static ExtractorLogger* make_logger(FormatType, OutputType, const std::vector<std::string>&);

    ExtractorLogger() = delete;
    ExtractorLogger(const ExtractorLogger&) = delete;
    ExtractorLogger& operator=(const ExtractorLogger&) = delete;
    ExtractorLogger(ExtractorLogger&&) = delete;

    virtual ~ExtractorLogger() = default;

    virtual void add_header() {}
    virtual void add_footer() {}
    // FIXIT-P: replace Value type designed for parsing with a better type
    virtual void add_field(const char*, const snort::Value&) {}

    virtual void open_record() {}
    virtual void close_record() {}

protected:
    ExtractorLogger(const std::vector<std::string>& fns) : fields_name(fns) {}

    const std::vector<std::string>& fields_name;
};

#endif
