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
#include "trace_log.h"

using namespace snort;

#define trace_help "configure trace log messages"
#define s_name "trace"

TraceModule::TraceModule() : Module(s_name, trace_help)
{
    generate_params();
}

void TraceModule::generate_params()
{
    auto modules = snort::ModuleManager::get_all_modules();
    for ( const auto* module : modules )
    {
        const TraceOption* trace_options = module->get_trace_options();
        if ( trace_options && strcmp(module->get_name(), "snort") != 0 )
        {
            auto& module_trace_options = configured_trace_options[module->get_name()];
            std::string module_trace_help(module->get_name());
            module_trace_help += " module trace options";
            modules_help.emplace_back(module_trace_help);

            module_ranges.emplace_back();
            auto& module_range = module_ranges.back();

            module_range.emplace_back(DEFAULT_TRACE_OPTION_NAME, Parameter::PT_INT, "0:255", nullptr,
                "enable all trace options");

            if ( !trace_options->name )
                module_trace_options[DEFAULT_TRACE_OPTION_NAME] = false;

            while ( trace_options->name )
            {
                module_range.emplace_back(trace_options->name,
                    Parameter::PT_INT, "0:255", nullptr, trace_options->help);

                module_trace_options[trace_options->name] = false;
                ++trace_options;
            }

            module_range.emplace_back(nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr);

            modules_params.emplace_back(module->get_name(), Parameter::PT_TABLE, module_range.data(),
                nullptr, modules_help.back().c_str());
        }
    }

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

        { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
    };

    const static Parameter trace_params[] =
    {
        { "modules", Parameter::PT_TABLE, modules_params.data(), nullptr, "modules trace option" },

        { "constraints", Parameter::PT_TABLE, trace_constraints_params,
            nullptr, "trace filtering constraints" },

        { "output", Parameter::PT_ENUM, "stdout | syslog", nullptr,
            "output method for trace log messages" },

        { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
    };

    set_params(trace_params);
}

bool TraceModule::begin(const char* fqn, int, SnortConfig* sc)
{
    if ( !strcmp(fqn, "trace") )
    {
        // Init default output type based on Snort run-mode
        if ( sc->test_mode() )
            log_output_type = OUTPUT_TYPE_NO_INIT;
        else if ( sc->daemon_mode() or sc->log_syslog() )
            log_output_type = OUTPUT_TYPE_SYSLOG;
        else
            log_output_type = OUTPUT_TYPE_STDOUT;

        reset_configured_trace_options();
    }
    return true;
}

void TraceModule::reset_configured_trace_options()
{
    for ( auto& module_trace_options : configured_trace_options )
        for ( auto& trace_options : module_trace_options.second )
            trace_options.second = false;
}

bool TraceModule::set(const char* fqn, Value& v, SnortConfig* sc)
{
    if ( v.is("output") )
    {
        if ( sc->test_mode() )
            return true;

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
    else if ( strstr(fqn, "trace.modules.") == fqn )
    {
        std::string module_name = find_module(fqn);
        if ( strcmp(v.get_name(), DEFAULT_TRACE_OPTION_NAME) == 0 )
        {
            const auto& trace_options = configured_trace_options[module_name];
            for ( const auto& trace_option : trace_options )
                if ( !trace_option.second )
                    sc->trace_config->set_trace(module_name, trace_option.first, v.get_uint8());
            return true;
        }
        else
        {
            bool res = sc->trace_config->set_trace(module_name, v.get_name(), v.get_uint8());
            configured_trace_options[module_name][v.get_name()] = res;
            return res;
        }
    }
    else if ( strstr(fqn, "trace.constraints.") == fqn )
    {
        if ( !sc->trace_config->constraints )
            sc->trace_config->constraints = new snort::PacketConstraints;

        auto& cs = *sc->trace_config->constraints;

        if ( v.is("ip_proto") )
        {
            cs.ip_proto = static_cast<IpProtocol>(v.get_uint8());
            cs.set_bits |= PacketConstraints::SetBits::IP_PROTO;
        }
        else if ( v.is("src_port") )
        {
            cs.src_port = v.get_uint16();
            cs.set_bits |= PacketConstraints::SetBits::SRC_PORT;
        }
        else if ( v.is("dst_port") )
        {
            cs.dst_port = v.get_uint16();
            cs.set_bits |= PacketConstraints::SetBits::DST_PORT;
        }
        else if ( v.is("src_ip") )
        {
            const char* str = v.get_string();
            if ( cs.src_ip.set(str) != SFIP_SUCCESS )
                return false;

            cs.set_bits |= PacketConstraints::SetBits::SRC_IP;
        }
        else if ( v.is("dst_ip") )
        {
            const char* str = v.get_string();
            if ( cs.dst_ip.set(str) != SFIP_SUCCESS )
                return false;

            cs.set_bits |= PacketConstraints::SetBits::DST_IP;
        }

        return true;
    }

    return false;
}

bool TraceModule::end(const char* fqn, int, SnortConfig* sc)
{
    if ( !strcmp(fqn, "trace") )
    {
        switch ( log_output_type )
        {
            case OUTPUT_TYPE_STDOUT:
                sc->trace_config->logger_factory = new StdoutLoggerFactory();
                break;
            case OUTPUT_TYPE_SYSLOG:
                sc->trace_config->logger_factory = new SyslogLoggerFactory();
                break;
            case OUTPUT_TYPE_NO_INIT:
                sc->trace_config->logger_factory = nullptr;
            default:
                break;
        }

        // "output=syslog" config override case
        // do not closelog() here since it will be closed in Snort::clean_exit()
        if ( !sc->log_syslog() and log_output_type == OUTPUT_TYPE_SYSLOG
             and !local_syslog )
        {
            local_syslog = true;
            openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON);
        }
    }

    return true;
}

std::string TraceModule::find_module(const char* fqn) const
{
    std::string module_name;
    const std::string config_name(fqn);
    const std::string pattern = "trace.modules.";
    size_t start_pos = config_name.find(pattern);
    if ( start_pos != std::string::npos )
    {
        start_pos += pattern.size();
        size_t end_pos = config_name.find(".", start_pos);
        if ( end_pos != std::string::npos )
            module_name = config_name.substr(start_pos, end_pos - start_pos);
    }
    return module_name;
}

