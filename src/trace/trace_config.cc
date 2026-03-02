//--------------------------------------------------------------------------
// Copyright (C) 2020-2026 Cisco and/or its affiliates. All rights reserved.
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
#include "managers/plugin_manager.h"
#include "packet_io/packet_constraints.h"
#include "trace_api.h"
#include "trace_parser.h"


using namespace snort;

TraceConfig::TraceConfig()
{ }

TraceConfig::TraceConfig(const TraceConfig& other)
    : TraceConfig()
{
    ntuple = other.ntuple;
    timestamp = other.timestamp;
    output_traces = other.output_traces;
    if ( other.constraints )
        constraints = new PacketConstraints(*other.constraints);
    load_traces();
}

TraceConfig::~TraceConfig()
{
    delete constraints;
    constraints = nullptr;
}

bool TraceConfig::set_trace(const std::string& module_name, const std::string& trace_option_name,
    uint8_t trace_level)
{
    const Module* mod = PluginManager::get_module(module_name.c_str());

    for ( auto& trace : traces )
    {
        if ( module_name == trace.module_name() )
            return trace.set(trace_option_name, trace_level, mod);
    }
    return false;
}

void TraceConfig::load_traces()
{
    if ( !traces.empty() )
        return;

    auto modules = PluginManager::get_all_modules();

    for ( auto* module : modules )
        traces.emplace_back(module);
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

