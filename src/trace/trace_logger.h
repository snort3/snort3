//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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
// trace_logger.h author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifndef TRACE_LOGGER_H
#define TRACE_LOGGER_H

#include <cstdint>

namespace snort
{
struct Packet;

class TraceLogger
{
public:
    virtual ~TraceLogger() = default;

    virtual void log(const char* log_msg, const char* name,
        uint8_t log_level, const char* trace_option, const Packet* p) = 0;

    void set_ntuple(bool flag)
    { ntuple = flag; }

    void set_timestamp(bool flag)
    { timestamp = flag; }

protected:
    bool ntuple = false;
    bool timestamp = false;
};

class TraceLoggerFactory
{
public:
    virtual ~TraceLoggerFactory() = default;

    virtual TraceLogger* instantiate() = 0;
};
}

#endif // TRACE_LOGGER_H

