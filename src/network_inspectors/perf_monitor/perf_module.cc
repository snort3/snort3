//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

// perf_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_FLATBUFFERS
#define FLATBUFFERS_ENUM " | flatbuffers"
#else
#define FLATBUFFERS_ENUM
#endif

#include "perf_module.h"

#include "managers/module_manager.h"

//-------------------------------------------------------------------------
// perf attributes
//-------------------------------------------------------------------------

static const Parameter module_params[] =
{
    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "name of the module" },

    { "pegs", Parameter::PT_STRING, nullptr, nullptr,
      "list of statistics to track or empty for all counters" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr },
};

static const Parameter s_params[] =
{
    { "base", Parameter::PT_BOOL, "nullptr", "true",
      "enable base statistics" },

    { "cpu", Parameter::PT_BOOL, "nullptr", "false",
      "enable cpu statistics" },

    { "flow", Parameter::PT_BOOL, nullptr, "false",
      "enable traffic statistics" },

    { "flow_ip", Parameter::PT_BOOL, nullptr, "false",
      "enable statistics on host pairs" },

    { "packets", Parameter::PT_INT, "0:", "10000",
      "minimum packets to report" },

    { "seconds", Parameter::PT_INT, "1:", "60",
      "report interval" },

    { "flow_ip_memcap", Parameter::PT_INT, "8200:", "52428800",
      "maximum memory in bytes for flow tracking" },

    { "max_file_size", Parameter::PT_INT, "4096:", "1073741824",
      "files will be rolled over if they exceed this size" },

    { "flow_ports", Parameter::PT_INT, "0:65535", "1023",
      "maximum ports to track" },

    { "output", Parameter::PT_ENUM, "file | console", "file",
      "output location for stats" },

    { "modules", Parameter::PT_LIST, module_params, nullptr,
      "gather statistics from the specified modules" },

    { "format", Parameter::PT_ENUM, "csv | text | json" FLATBUFFERS_ENUM, "csv",
      "output format for stats" },

    { "summary", Parameter::PT_BOOL, nullptr, "false",
      "output summary at shutdown" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// perf attributes
//-------------------------------------------------------------------------

PerfMonModule::PerfMonModule() :
    Module(PERF_NAME, PERF_HELP, s_params)
{ }

ProfileStats* PerfMonModule::get_profile() const
{ return &perfmonStats; }

bool PerfMonModule::set(const char*, Value& v, SnortConfig*)
{

    if ( v.is("base") )
    {
        if ( v.get_bool() )
            config.perf_flags |= PERF_BASE;
        else
            config.perf_flags &= ~PERF_BASE; //Clear since true by default
    }
    else if ( v.is("cpu") )
    {
        if ( v.get_bool() )
            config.perf_flags |= PERF_CPU;
    }
    else if ( v.is("flow") )
    {
        if ( v.get_bool() )
            config.perf_flags |= PERF_FLOW;
    }
    else if ( v.is("flow_ip") )
    {
        if ( v.get_bool() )
            config.perf_flags |= PERF_FLOWIP;
    }
    else if ( v.is("packets") )
    {
        config.pkt_cnt = v.get_long();
    }
    else if ( v.is("seconds") )
    {
        config.sample_interval = v.get_long();
        if ( config.sample_interval == 0 )
            config.perf_flags |= PERF_SUMMARY;
    }
    else if ( v.is("flow_ip_memcap") )
    {
        config.flowip_memcap = v.get_long();
    }
    else if ( v.is("max_file_size") )
        config.max_file_size = v.get_long() - ROLLOVER_THRESH;

    else if ( v.is("flow_ports") )
    {
        config.flow_max_port_to_track = v.get_long();
    }
    else if ( v.is("output") )
    {
        config.output = (PerfOutput)v.get_long();
    }
    else if ( v.is("format") )
    {
        config.format = (PerfFormat)v.get_long();
    }
    else if ( v.is("name") )
    {
        mod_name = v.get_string();
    }
    else if ( v.is("pegs") )
    {
        mod_pegs = v.get_string();
    }
    else if ( v.is("summary") )
    {
        if ( v.get_bool() )
            config.perf_flags |= PERF_SUMMARY;
    }
    else if ( v.is("modules") )
    {
        return true;
    }
    else
        return false;

    return true;
}

bool PerfMonModule::begin(const char* fqn, int, SnortConfig*)
{
    if ( !strcmp(fqn, "perf_monitor.modules") )
    {
        mod_name.clear();
        mod_pegs.clear();
    }
    else
        memset(static_cast<PerfConfigBase*>(&config), 0, sizeof(config));

    return true;
}

static bool add_module(PerfConfig& config, Module *mod, std::string& pegs)
{
    const PegInfo* peg_info;
    std::string tok;
    Value v(pegs.c_str());
    unsigned t_count = 0;

    if ( !mod )
        return false;

    config.modules.push_back(mod);
    config.mod_peg_idxs.push_back(std::vector<unsigned>());

    peg_info = mod->get_pegs();

    for ( v.set_first_token(); v.get_next_token(tok); t_count++ )
    {
        bool found = false;

        for ( int i = 0; peg_info[i].name; i++ )
        {
            if ( !strcmp(tok.c_str(), peg_info[i].name) )
            {
                config.mod_peg_idxs.back().push_back(i);
                found = true;
                break;
            }
        }
        if ( !found )
            return false;
    }
    if ( !t_count && peg_info )
        for ( int i = 0; peg_info[i].name; i++ )
            config.mod_peg_idxs.back().push_back(i);
    return true;
}

bool PerfMonModule::end(const char* fqn, int idx, SnortConfig*)
{
    if ( !idx )
    {
        if ( !config.modules.size() )
        {
            auto modules = ModuleManager::get_all_modules();
            std::string empty;

            for ( auto& mod : modules )
            {
                if ( !add_module(config, mod, empty) )
                    return false;
            }
        }
        return true;
    }

    if ( !strcmp(fqn, "perf_monitor.modules") && mod_name.size() > 0 )
        return add_module(config, ModuleManager::get_module(mod_name.c_str()), mod_pegs);

    return true;
}

void PerfMonModule::get_config(PerfConfig& cfg)
{
    cfg = config;
}

const PegInfo* PerfMonModule::get_pegs() const
{ return simple_pegs; }

PegCount* PerfMonModule::get_counts() const
{ return (PegCount*)&pmstats; }

