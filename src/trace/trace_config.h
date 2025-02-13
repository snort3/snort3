//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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
// trace_config.h author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifndef TRACE_CONFIG_H
#define TRACE_CONFIG_H

#include "trace.h"

namespace snort
{
struct PacketConstraints;
class TraceLoggerFactory;
}

class TraceConfig
{
public:
    TraceConfig();
    TraceConfig(const TraceConfig&);
    ~TraceConfig();

    void setup_module_trace() const;
    bool set_trace(const std::string& module_name,
        const std::string& trace_option_name, uint8_t trace_level);

    void clear();
    void clear_traces();

public:
    snort::TraceLoggerFactory* logger_factory = nullptr;
    snort::PacketConstraints* constraints = nullptr;

    bool ntuple = false;
    bool timestamp = false;
    bool initialized = false;

private:
    Traces traces;
};

#endif // TRACE_CONFIG_H

