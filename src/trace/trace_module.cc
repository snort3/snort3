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
// trace_module.cc author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "trace_module.h"

#include <functional>
#include <sstream>

#include "main/snort_config.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "managers/trace_logger_manager.h"
#include "packet_io/packet_constraints.h"

#include "trace_api.h"
#include "trace_config.h"
#include "trace_parser.h"
#include "trace_swap.h"

using namespace snort;

// Helpers

static std::string extract_module_option(const char* fqn)
{
    std::string option_name;
    const std::string config_name(fqn);
    const std::string pattern = "trace.modules.";
    size_t start_pos = config_name.find(pattern);
    if ( start_pos != std::string::npos )
    {
        start_pos += pattern.size();
        size_t end_pos = config_name.find(".", start_pos);
        size_t option_len = ( end_pos != std::string::npos ) ? end_pos - start_pos
            : config_name.size() - start_pos;

        option_name = config_name.substr(start_pos, option_len);
    }
    return option_name;
}

std::function<const char*()> get_trace_loggers = []()
{ return PluginManager::get_available_plugins(PT_TRACE, "none |"); };

// Module stuff

#define trace_help "configure trace log messages"
#define s_name "trace"

const static Parameter trace_constraints_params[] =
{
    { "ip_proto", Parameter::PT_INT, "0:255", nullptr,
      "numerical IP protocol ID filter" },

    { "src_ip", Parameter::PT_STRING, nullptr, nullptr,
      "source IP address filter" },

    { "src_port", Parameter::PT_INT, "0:65535", nullptr,
      "source port filter" },

    { "dst_ip", Parameter::PT_STRING, nullptr, nullptr,
      "destination IP address filter" },

    { "dst_port", Parameter::PT_INT, "0:65535", nullptr,
      "destination port filter" },

    { "match", Parameter::PT_BOOL, nullptr, "true",
      "use constraints to filter traces" },

    { "tenants", Parameter::PT_STRING, nullptr, nullptr,
      "tenants filter" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static Parameter trace_params[] =
{
    { "output", Parameter::PT_DYNAMICS, (void*)&get_trace_loggers, "stdout_trace",
      "output method(s) for trace log messages" },

    { "ntuple", Parameter::PT_BOOL, nullptr, "false",
      "print packet n-tuple info with trace messages" },

    { "timestamp", Parameter::PT_BOOL, nullptr, "false",
      "print message timestamps with trace messages" },

    { "constraints", Parameter::PT_TABLE, trace_constraints_params,
      nullptr, "trace filtering constraints" },

    { "modules", Parameter::PT_TABLE, nullptr, nullptr, "modules trace option" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Command s_commands[] =
{
    { "set", TraceSwapParams::set, trace_params, "set trace configuration" },
    { "clear", TraceSwapParams::clear, nullptr, "clear trace configuration" },
    { nullptr, nullptr, nullptr, nullptr }
};

TraceModule::TraceModule() : Module(s_name, trace_help) { }

TraceModule::~TraceModule()
{ delete trace_parser; }

void TraceModule::init()
{
    generate_params();
    TraceSwapParams::set_params(get_parameters());
}

void TraceModule::reset()
{
    modules_params.clear();
    module_ranges.clear();
    modules_help.clear();
    outputs.clear();

    delete trace_parser;
    trace_parser = nullptr;

    set_params(nullptr);
}

void TraceModule::capture_outputs(TraceConfig* tc)
{
    std::stringstream ss(outputs);
    std::string tok;

    while ( ss >> tok )
    {
        if ( tok != "none" )
            tc->output_traces.push_back(tok);
    }
}

const Command* TraceModule::get_commands() const
{
    return s_commands;
}

void TraceModule::generate_params()
{
    auto modules = PluginManager::get_all_modules();
    for ( const auto* module : modules )
    {
        const TraceOption* trace_options = module->get_trace_options();
        if ( trace_options )
        {
            std::string module_trace_help(module->get_name());
            module_trace_help += " module trace options";
            modules_help.emplace_back(module_trace_help);

            module_ranges.emplace_back();
            auto& module_range = module_ranges.back();

            module_range.emplace_back(DEFAULT_TRACE_OPTION_NAME, Parameter::PT_INT, "0:255", nullptr,
                "enable all trace options");

            while ( trace_options->name )
            {
                module_range.emplace_back(trace_options->name,
                    Parameter::PT_INT, "0:255", nullptr, trace_options->help);

                ++trace_options;
            }

            module_range.emplace_back(nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr);

            modules_params.emplace_back(module->get_name(), Parameter::PT_TABLE, module_range.data(),
                nullptr, modules_help.back().c_str());
        }
    }

    std::sort(modules_params.begin(), modules_params.end(),
        [](const Parameter& l, const Parameter& r) { return (strcmp(l.name, r.name) < 0); });

    modules_params.emplace(modules_params.begin(), DEFAULT_TRACE_OPTION_NAME, Parameter::PT_INT,
        "0:255", nullptr, "enable trace for all modules");

    modules_params.emplace_back(nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr);

    Parameter* p = trace_params;

    while ( p->name and strcmp(p->name, "modules") )
        p++;

    assert(p);
    p->range = modules_params.data();

    set_params(trace_params);
}

bool TraceModule::begin(const char* fqn, int, SnortConfig* sc)
{
    if ( !strcmp(fqn, "trace") )
    {
        sc->trace_config->load_traces();
        trace_parser = new TraceParser(*sc->trace_config);
    }
    return true;
}

bool TraceModule::set(const char* fqn, Value& v, SnortConfig*)
{
    if ( v.is("output") )
        outputs = v.get_string();

    else if ( v.is("ntuple") )
        trace_parser->get_trace_config().ntuple = v.get_bool();

    else if ( v.is("timestamp") )
        trace_parser->get_trace_config().timestamp = v.get_bool();

    else if ( strstr(fqn, "trace.modules.") == fqn )
    {
        std::string option_name = extract_module_option(fqn);
        return trace_parser->set_traces(option_name, v);
    }
    else
    {
        assert(strstr(fqn, "trace.constraints.") == fqn);
        return trace_parser->set_constraints(v);
    }
    return true;
}

bool TraceModule::end(const char* fqn, int, SnortConfig*)
{
    if ( !strcmp(fqn, "trace") )
    {
        assert(trace_parser);
        trace_parser->get_trace_config().initialized = true;
        trace_parser->finalize_constraints();
        delete trace_parser;
        trace_parser = nullptr;
    }

    return true;
}

