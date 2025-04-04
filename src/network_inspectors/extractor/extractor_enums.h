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
// extractor_enums.h author Cisco

#ifndef EXTRACTOR_ENUMS_H
#define EXTRACTOR_ENUMS_H

#include <cstdint>

class ServiceType
{
public:
    enum Value : uint8_t
    {
        HTTP,
        FTP,
        CONN,
        DNS,
        ANY,
        MAX
    };

    ServiceType() = default;
    constexpr ServiceType(Value a) : v(a) {}
    template<typename T> constexpr ServiceType(T a) : v(Value(a)) {}

    constexpr operator Value() const { return v; }
    explicit operator bool() const = delete;

    const char* c_str() const
    {
        switch (v)
        {
        case HTTP:
            return "http";
        case FTP:
            return "ftp";
        case CONN:
            return "conn";
        case DNS:
            return "dns";
        case ANY: // fallthrough
        case MAX: // fallthrough
        default:
            return "(not set)";
        }
    }

private:
    Value v = ANY;
};

class FormatType
{
public:
    enum Value : uint8_t
    {
        CSV,
        TSV,
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
        case TSV:
            return "tsv";
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

class TimeType
{
public:
    enum Value : uint8_t
    {
        SNORT,
        SNORT_YY,
        UNIX,
        UNIX_S,
        UNIX_US,
        MAX
    };

    TimeType() = default;
    constexpr TimeType(Value a) : v(a) {}
    template<typename T> constexpr TimeType(T a) : v((Value)a) {}

    constexpr operator Value() const { return v; }
    explicit operator bool() const = delete;

    const char* c_str() const
    {
        switch (v)
        {
        case SNORT:
            return "snort";
        case SNORT_YY:
            return "snort_yy";
        case UNIX:
            return "unix";
        case UNIX_S:
            return "unix_s";
        case UNIX_US:
            return "unix_us";
        case MAX: // fallthrough
        default:
            return "(not set)";
        }
    }

private:
    Value v = UNIX;
};

#endif
