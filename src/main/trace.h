//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
#include <vector>

#include "framework/value.h"
#include "main/snort_types.h"

#define DEFAULT_TRACE_OPTION 0
#define DEFAULT_LOG_LEVEL 1

typedef uint8_t TraceOption;
typedef uint8_t TraceLevel;


struct TraceOptionString
{
    const char* alias;
    TraceOption option;
};

namespace snort
{
struct SO_PUBLIC Trace
{
    Trace(const char*, const TraceOptionString*, size_t);
    Trace(const char*);
    ~Trace() = default;

    bool set(const snort::Value&);
    void reset();
    void enable();

    const char* module_name() const
    { return mod_name; }

    const char* option_name(size_t index) const
    {
        assert(index < option_levels.size());
        return options[index].alias;
    }

    bool enabled(TraceOption trace_option, TraceLevel log_level = DEFAULT_LOG_LEVEL) const
    {
        assert(trace_option < option_levels.size());
        return option_levels[trace_option] >= log_level;
    }

    const TraceOptionString* options;
    std::vector<TraceLevel> option_levels;
    std::vector<bool> config_options;
    const char* mod_name;
};
}

#endif
