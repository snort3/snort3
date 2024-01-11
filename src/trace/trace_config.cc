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
// trace_config.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "trace_config.h"

#include <cstring>

#include "framework/module.h"
#include "framework/packet_constraints.h"
#include "managers/module_manager.h"

#include "trace_logger.h"

using namespace snort;

TraceConfig::TraceConfig()
{
    auto modules = ModuleManager::get_all_modules();
    for ( auto* module : modules )
    {
        if ( module->get_trace_options() )
            traces.emplace_back(*module);
    }
}

TraceConfig::TraceConfig(const TraceConfig& other)
    : TraceConfig()
{
    traces = other.traces;
    ntuple = other.ntuple;
    timestamp = other.timestamp;
    if ( other.constraints )
        constraints = new PacketConstraints(*other.constraints);
}

TraceConfig::~TraceConfig()
{
    delete logger_factory;
    logger_factory = nullptr;

    delete constraints;
    constraints = nullptr;
}

bool TraceConfig::set_trace(const std::string& module_name, const std::string& trace_option_name,
    uint8_t trace_level)
{
    for ( auto& trace : traces )
    {
        if ( module_name == trace.module_name() )
            return trace.set(trace_option_name, trace_level);
    }
    return false;
}

void TraceConfig::clear()
{
    clear_traces();
    initialized = false;
    delete logger_factory;
    logger_factory = nullptr;
}

void TraceConfig::clear_traces()
{
    for ( auto& trace : traces )
        trace.clear();
}

void TraceConfig::setup_module_trace() const
{
    for ( const auto& trace : traces )
        trace.set_module_trace();
}

