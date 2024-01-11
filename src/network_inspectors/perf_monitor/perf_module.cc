//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "perf_module.h"

#include <lua.hpp>

#include "control/control.h"
#include "log/messages.h"
#include "main/analyzer_command.h"
#include "main/snort.h"
#include "managers/module_manager.h"

#include "perf_monitor.h"
#include "perf_pegs.h"
#include "perf_reload_tuner.h"

using namespace snort;

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
    { "base", Parameter::PT_BOOL, nullptr, "true",
      "enable base statistics" },

    { "cpu", Parameter::PT_BOOL, nullptr, "false",
      "enable cpu statistics" },

    { "flow", Parameter::PT_BOOL, nullptr, "false",
      "enable traffic statistics" },

    { "flow_ip", Parameter::PT_BOOL, nullptr, "false",
      "enable statistics on host pairs" },

    { "packets", Parameter::PT_INT, "0:max32", "10000",
      "minimum packets to report" },

    { "seconds", Parameter::PT_INT, "0:max32", "60",
      "report interval" },

    { "flow_ip_memcap", Parameter::PT_INT, "236:maxSZ", "52428800",
      "maximum memory in bytes for flow tracking" },

    { "max_file_size", Parameter::PT_INT, "4096:max53", "1073741824",
      "files will be rolled over if they exceed this size" },

    { "flow_ports", Parameter::PT_INT, "0:65535", "1023",
      "maximum ports to track" },

    { "output", Parameter::PT_ENUM, "file | console", "file",
      "output location for stats" },

    { "modules", Parameter::PT_LIST, module_params, nullptr,
      "gather statistics from the specified modules" },

    { "format", Parameter::PT_ENUM, "csv | text | json", "csv",
      "output format for stats" },

    { "summary", Parameter::PT_BOOL, nullptr, "false",
      "output summary at shutdown" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class PerfMonFlowIPDebug : public AnalyzerCommand
{
public:
    PerfMonFlowIPDebug(PerfConstraints* cs, bool en, PerfMonitor* pm) :
        enable(en), constraints(cs), perf_monitor(pm) { }
    ~PerfMonFlowIPDebug() override
    { perf_monitor->swap_constraints(constraints); }

    bool execute(Analyzer&, void**) override;
    const char* stringify() override { return "FLOW_IP_PROFILING"; }

private:
    bool enable;
    PerfConstraints* constraints;
    PerfMonitor* perf_monitor;
};

static const Parameter flow_ip_profiling_params[] =
{
    { "seconds", Parameter::PT_INT, "1:max32", nullptr,
      "report interval" },

    { "packets", Parameter::PT_INT, "0:max32", nullptr,
      "minimum packets to report" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

bool PerfMonFlowIPDebug::execute(Analyzer&, void**)
{
    if (enable)
        perf_monitor->enable_profiling(constraints);
    else
        perf_monitor->disable_profiling(constraints);

    return true;
}

static int enable_flow_ip_profiling(lua_State* L)
{
    PerfMonitor* perf_monitor =
        (PerfMonitor*)InspectorManager::get_inspector(PERF_NAME, true);

    if (!perf_monitor)
    {
        LogMessage("perf_monitor is not configured, "
            "flow ip profiling cannot be enabled.\n");
        return 0;
    }

    auto* new_constraints = new PerfConstraints(true, luaL_optint(L, 1, 0),
        luaL_optint(L, 2, 0));

    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    main_broadcast_command(new PerfMonFlowIPDebug(new_constraints, true, perf_monitor), ctrlcon);

    LogMessage("Enabling flow ip profiling with sample interval %d packet count %d\n",
        new_constraints->sample_interval, new_constraints->pkt_cnt);

    return 0;
}

static int disable_flow_ip_profiling(lua_State* L)
{
    PerfMonitor* perf_monitor =
        (PerfMonitor*)InspectorManager::get_inspector(PERF_NAME, true);

    if (!perf_monitor)
    {
        LogMessage("Attempting to disable flow ip profiling when "
            "perf_monitor is not configured\n");
        return 0;
    }

    if (!perf_monitor->is_flow_ip_enabled())
    {
        LogMessage("Attempting to disable flow ip profiling when "
            "it is not running\n");
        return 0;
    }

    auto* new_constraints = perf_monitor->get_original_constraints();

    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    main_broadcast_command(new PerfMonFlowIPDebug(new_constraints, false, perf_monitor), ctrlcon);

    LogMessage("Disabling flow ip profiling\n");

    return 0;
}

static int show_flow_ip_profiling(lua_State* L)
{
    bool status = false;
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);

    PerfMonitor* perf_monitor = (PerfMonitor*)InspectorManager::get_inspector(PERF_NAME, true);

    if (perf_monitor)
        status = perf_monitor->is_flow_ip_enabled();
    else
        LogRespond(ctrlcon, "perf_monitor is not configured\n");

    LogRespond(ctrlcon, "Snort flow ip profiling is %s\n", status ? "enabled" : "disabled");

    return 0;
}

static const Command perf_module_cmds[] =
{
    { "enable_flow_ip_profiling", enable_flow_ip_profiling,
      flow_ip_profiling_params, "enable statistics on host pairs" },

    { "disable_flow_ip_profiling", disable_flow_ip_profiling,
      nullptr, "disable statistics on host pairs" },

    { "show_flow_ip_profiling", show_flow_ip_profiling,
      nullptr, "show status of statistics on host pairs" },

    { nullptr, nullptr, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// perf attributes
//-------------------------------------------------------------------------

PerfMonModule::PerfMonModule() :
    Module(PERF_NAME, PERF_HELP, s_params)
{ }

PerfMonModule::~PerfMonModule()
{
    if (config)
        delete config;
}

ProfileStats* PerfMonModule::get_profile() const
{ return &perfmonStats; }

bool PerfMonModule::set(const char*, Value& v, SnortConfig*)
{

    if ( v.is("base") )
    {
        if ( v.get_bool() )
            config->perf_flags |= PERF_BASE;
        else
            config->perf_flags &= ~PERF_BASE; //Clear since true by default
    }
    else if ( v.is("cpu") )
    {
        if ( v.get_bool() )
            config->perf_flags |= PERF_CPU;
    }
    else if ( v.is("flow") )
    {
        if ( v.get_bool() )
            config->perf_flags |= PERF_FLOW;
    }
    else if ( v.is("flow_ip") )
    {
        if ( v.get_bool() )
            config->perf_flags |= PERF_FLOWIP;
    }
    else if ( v.is("packets") )
    {
        config->pkt_cnt = v.get_uint32();
    }
    else if ( v.is("seconds") )
    {
        config->sample_interval = v.get_uint32();
    }
    else if ( v.is("flow_ip_memcap") )
    {
        config->flowip_memcap = v.get_size();
    }
    else if ( v.is("max_file_size") )
        config->max_file_size = v.get_uint64() - ROLLOVER_THRESH;

    else if ( v.is("flow_ports") )
    {
        config->flow_max_port_to_track = v.get_uint16();
    }
    else if ( v.is("output") )
    {
        config->output = (PerfOutput)v.get_uint8();
    }
    else if ( v.is("format") )
    {
        config->format = (PerfFormat)v.get_uint8();
    }
    else if ( v.is("name") )
    {
        config->modules.back().set_name(v.get_string());
    }
    else if ( v.is("pegs") )
    {
        config->modules.back().set_peg_names(v);
    }
    else if ( v.is("summary") )
    {
        if ( v.get_bool() )
            config->perf_flags |= PERF_SUMMARY;
    }
    else if ( v.is("modules") )
    {
        return true;
    }
    return true;
}

bool PerfMonModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( strcmp(fqn, "perf_monitor") == 0 )
    {
        assert(config == nullptr);
        config = new PerfConfig;
    }
    if ( idx != 0 && strcmp(fqn, "perf_monitor.modules") == 0 )
        config->modules.emplace_back(ModuleConfig());

    return true;
}

bool PerfMonModule::end(const char* fqn, int idx, SnortConfig* sc)
{

    if ( Snort::is_reloading() && strcmp(fqn, "perf_monitor") == 0 )
        sc->register_reload_handler(new PerfMonReloadTuner(config->flowip_memcap));

    if ( idx != 0 && strcmp(fqn, "perf_monitor.modules") == 0 )
        return config->modules.back().confirm_parse();

    return true;
}

PerfConfig* PerfMonModule::get_config()
{
    PerfConfig* tmp = config;

    tmp->constraints->flow_ip_enabled = config->perf_flags & PERF_FLOWIP;
    tmp->constraints->sample_interval = config->sample_interval;
    tmp->constraints->pkt_cnt = config->pkt_cnt;

    config = nullptr;
    return tmp;
}

const PegInfo* PerfMonModule::get_pegs() const
{ return perf_module_pegs; }

PegCount* PerfMonModule::get_counts() const
{ return (PegCount*)&pmstats; }

const Command* PerfMonModule::get_commands() const
{ return perf_module_cmds; }

void ModuleConfig::set_name(const std::string& name)
{ this->name = name; }

void ModuleConfig::set_peg_names(Value& peg_names)
{
    std::string tok;
    peg_names.set_first_token();

    while ( peg_names.get_next_token(tok) )
        this->peg_names[tok] = false;
}

bool ModuleConfig::confirm_parse()
{
    // asking for pegs without specifying the module name doesn't make sense
    if ( name.empty() && !peg_names.empty() )
        return false;

    return true;
}
bool ModuleConfig::resolve()
{
    ptr = ModuleManager::get_module(name.c_str());
    if ( ptr == nullptr )
    {
        ParseError("Perf monitor is unable to find the %s module.\n", name.c_str());
        return false;
    }

    const PegInfo* peg_info = ptr->get_pegs();
    if ( !peg_info )
        return true; // classifications does this. it's valid.

    if ( peg_names.empty() )
    {
        for ( unsigned i = 0; peg_info[i].name != nullptr; i++ )
            pegs.emplace_back(i);
    }
    else
    {
        for ( unsigned i = 0; peg_info[i].name != nullptr; i++ )
        {
            auto peg_ittr = peg_names.find(peg_info[i].name);

            if ( peg_ittr != peg_names.end() )
            {
                peg_ittr->second = true;
                pegs.emplace_back(i);
            }
        }

        std::for_each(peg_names.cbegin(), peg_names.cend(),
            [this](const std::pair<const std::string, bool>& i)
            {
                if (!i.second)
                    ParseWarning(WARN_CONF, "Perf monitor is unable to find %s.%s count\n",
                        name.c_str(), i.first.c_str());
            });
    }
    name.clear();
    peg_names.clear();
    return true;
}

bool PerfConfig::resolve()
{
    if ( modules.empty() )
    {
        auto all_modules = ModuleManager::get_all_modules();
        for ( auto& mod : all_modules )
        {
            ModuleConfig cfg;
            cfg.set_name(mod->get_name());
            modules.emplace_back(cfg);
        }
    }

    for ( auto& mod : modules )
    {
        if ( !mod.resolve() )
            return false;

        if ( mod.ptr->counts_need_prep() )
            mods_to_prep.emplace_back(mod.ptr);
    }

    return true;
}
