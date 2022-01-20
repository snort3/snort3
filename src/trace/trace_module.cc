//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

#include <syslog.h>

#include "framework/packet_constraints.h"
#include "main/snort_config.h"
#include "managers/module_manager.h"

#include "trace_config.h"
#include "trace_loggers.h"
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

// Module stuff

#define trace_help "configure trace log messages"
#define s_name "trace"

TraceModule::TraceModule() : Module(s_name, trace_help)
{
    generate_params();
    TraceSwapParams::set_params(get_parameters());
}

TraceModule::~TraceModule()
{ delete trace_parser; }

const Command* TraceModule::get_commands() const
{ return TraceSwapParams::get_commands(); }

void TraceModule::generate_params()
{
    auto modules = snort::ModuleManager::get_all_modules();
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

        { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
    };

    const static Parameter trace_params[] =
    {
        { "modules", Parameter::PT_TABLE, modules_params.data(), nullptr, "modules trace option" },

        { "constraints", Parameter::PT_TABLE, trace_constraints_params,
          nullptr, "trace filtering constraints" },

        { "output", Parameter::PT_ENUM, "stdout | syslog", nullptr,
          "output method for trace log messages" },

        { "ntuple", Parameter::PT_BOOL, nullptr, "false",
          "print packet n-tuple info with trace messages" },

        { "timestamp", Parameter::PT_BOOL, nullptr, "false",
          "print message timestamps with trace messages" },

        { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
    };

    set_params(trace_params);
}

bool TraceModule::begin(const char* fqn, int, SnortConfig* sc)
{
    if ( !strcmp(fqn, "trace") )
    {
        trace_parser = new TraceParser(*sc->trace_config);

        // Init default output type based on Snort run-mode
        if ( sc->daemon_mode() or SnortConfig::log_syslog() )
            log_output_type = OUTPUT_TYPE_SYSLOG;
        else
            log_output_type = OUTPUT_TYPE_STDOUT;

    }
    return true;
}

bool TraceModule::set(const char* fqn, Value& v, SnortConfig*)
{
    if ( v.is("output") )
    {
        switch ( v.get_uint8() )
        {
            case OUTPUT_TYPE_STDOUT:
                log_output_type = OUTPUT_TYPE_STDOUT;
                break;
            case OUTPUT_TYPE_SYSLOG:
                log_output_type = OUTPUT_TYPE_SYSLOG;
                break;
            default:
                return false;
        }
        return true;
    }
    else if ( v.is("ntuple") )
    {
        trace_parser->get_trace_config().ntuple = v.get_bool();
        return true;
    }
    else if ( v.is("timestamp") )
    {
        trace_parser->get_trace_config().timestamp = v.get_bool();
        return true;
    }
    else if ( strstr(fqn, "trace.modules.") == fqn )
    {
        std::string option_name = extract_module_option(fqn);
        return trace_parser->set_traces(option_name, v);
    }
    else if ( strstr(fqn, "trace.constraints.") == fqn )
        return trace_parser->set_constraints(v);

    return false;
}

bool TraceModule::end(const char* fqn, int, SnortConfig* sc)
{
    if ( !strcmp(fqn, "trace") )
    {
        assert(trace_parser);

        if ( sc->dump_config_mode() )
            trace_parser->clear_traces();
        else
        {
            switch ( log_output_type )
            {
            case OUTPUT_TYPE_STDOUT:
                trace_parser->get_trace_config().logger_factory = new StdoutLoggerFactory();
                break;
            case OUTPUT_TYPE_SYSLOG:
                trace_parser->get_trace_config().logger_factory = new SyslogLoggerFactory();
                break;
            default:
                break;
            }

            // "output=syslog" config override case
            // do not closelog() here since it will be closed in Snort::clean_exit()
            if ( !SnortConfig::log_syslog() and log_output_type == OUTPUT_TYPE_SYSLOG
                and !local_syslog )
            {
                local_syslog = true;
                openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON);
            }

            trace_parser->finalize_constraints();
        }

        trace_parser->get_trace_config().initialized = true;

        delete trace_parser;
        trace_parser = nullptr;
    }

    return true;
}

