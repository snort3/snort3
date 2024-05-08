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
// trace.h author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifndef TRACE_H
#define TRACE_H

#include <cassert>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#define DEFAULT_TRACE_LOG_LEVEL 1
#define TRACE_CRITICAL_LEVEL 2
#define TRACE_ERROR_LEVEL 3
#define TRACE_WARNING_LEVEL 4
#define TRACE_INFO_LEVEL 6
#define TRACE_DEBUG_LEVEL 7
#define DEFAULT_TRACE_OPTION_ID 0
#define DEFAULT_TRACE_OPTION_NAME "all"

namespace snort
{
class Trace;
}

using TraceOptionID = uint8_t;
using TraceLevel = uint8_t;
using Traces = std::vector<snort::Trace>;
using ConfigTraceOptions = std::map<std::string, bool>;
using ModulesConfigTraceOptions = std::map<std::string, ConfigTraceOptions>;

namespace snort
{
class Module;

struct TraceOption
{
    TraceOption(const char* n, TraceOptionID tid, const char* h) :
        name(n), id(tid), help(h) {}

    const char* name;
    TraceOptionID id;
    const char* help;
};

class Trace
{
public:
    Trace(const Module& m);
    Trace& operator=(const Trace&);

    bool set(const std::string& option_name, uint8_t option_level);
    void set_module_trace() const;

    void clear();

    const char* module_name() const
    { return mod_name.c_str(); }

    const char* option_name(size_t index) const
    {
        assert(index < option_levels.size());
        return options[index].name;
    }

    bool enabled(TraceOptionID trace_option_id, TraceLevel log_level = DEFAULT_TRACE_LOG_LEVEL) const
    {
        assert(trace_option_id < option_levels.size());
        return option_levels[trace_option_id] >= log_level;
    }

private:
    std::string mod_name;
    const TraceOption* options;
    const Module& module;
    std::vector<TraceLevel> option_levels;
};
}

#endif

