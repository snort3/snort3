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

#include <sys/time.h>
#include <vector>

#include "sfip/sf_ip.h"

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
    static ExtractorLogger* make_logger(FormatType, OutputType);

    ExtractorLogger() = default;
    ExtractorLogger(const ExtractorLogger&) = delete;
    ExtractorLogger& operator=(const ExtractorLogger&) = delete;
    ExtractorLogger(ExtractorLogger&&) = delete;
    virtual ~ExtractorLogger() = default;

    virtual bool is_strict() const
    { return false; }
    virtual void set_fields(std::vector<const char*>& names)
    { field_names = names; }

    virtual void add_header() {}
    virtual void add_footer() {}

    virtual void add_field(const char*, const char*) {}
    virtual void add_field(const char*, const char*, size_t) {}
    virtual void add_field(const char*, uint64_t) {}
    virtual void add_field(const char*, struct timeval) {}
    virtual void add_field(const char*, const snort::SfIp&) {}

    virtual void open_record() {}
    virtual void close_record() {}

protected:
    std::vector<const char*> field_names;
};

#endif
