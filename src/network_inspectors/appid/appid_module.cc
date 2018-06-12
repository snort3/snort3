//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// appid_module.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: May 10, 2016

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_module.h"

#include <climits>
#include <lua.hpp>

#include "log/messages.h"
#include "main/analyzer_command.h"
#include "profiler/profiler.h"
#include "utils/util.h"

#include "app_info_table.h"
#include "appid_debug.h"
#include "appid_peg_counts.h"

using namespace snort;
using namespace std;

Trace TRACE_NAME(appid_module);

//-------------------------------------------------------------------------
// appid module
//-------------------------------------------------------------------------

THREAD_LOCAL ProfileStats appidPerfStats;
THREAD_LOCAL AppIdStats appid_stats;

static const Parameter s_params[] =
{
#ifdef USE_RNA_CONFIG
    { "conf", Parameter::PT_STRING, nullptr, nullptr,
      "RNA configuration file" },  // FIXIT-L eliminate reference to "RNA"
#endif
    // FIXIT-L: DECRYPT_DEBUG - Move this to ssl-module
#ifdef REG_TEST
    { "first_decrypted_packet_debug", Parameter::PT_INT, "0:", "0",
      "the first packet of an already decrypted SSL flow (debug single session only)" },
#endif
    { "memcap", Parameter::PT_INT, "0:", "0",
      "disregard - not implemented" },  // FIXIT-M implement or delete appid.memcap
    { "log_stats", Parameter::PT_BOOL, nullptr, "false",
      "enable logging of appid statistics" },
    { "app_stats_period", Parameter::PT_INT, "0:", "300",
      "time period for collecting and logging appid statistics" },
    { "app_stats_rollover_size", Parameter::PT_INT, "0:", "20971520",
      "max file size for appid stats before rolling over the log file" },
    { "app_stats_rollover_time", Parameter::PT_INT, "0:", "86400",
      "max time period for collection appid stats before rolling over the log file" },
    { "app_detector_dir", Parameter::PT_STRING, nullptr, nullptr,
      "directory to load appid detectors from" },
    { "instance_id", Parameter::PT_INT, "0:", "0",
      "instance id - ignored" },
    { "debug", Parameter::PT_BOOL, nullptr, "false",
      "enable appid debug logging" },
    { "dump_ports", Parameter::PT_BOOL, nullptr, "false",
      "enable dump of appid port information" },
    { "tp_appid_path", Parameter::PT_STRING, nullptr, nullptr,
      "path to third party appid dynamic library" },
    { "tp_appid_config", Parameter::PT_STRING, nullptr, nullptr,
      "path to third party appid configuration file" },
    { "log_all_sessions", Parameter::PT_BOOL, nullptr, "false",
      "enable logging of all appid sessions" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class AcAppIdDebug : public AnalyzerCommand
{
public:
    AcAppIdDebug(AppIdDebugSessionConstraints* cs);
    void execute(Analyzer&) override;
    const char* stringify() override { return "APPID_DEBUG"; }

private:
    AppIdDebugSessionConstraints constraints = { };
    bool enable = false;
};

AcAppIdDebug::AcAppIdDebug(AppIdDebugSessionConstraints* cs)
{
    if (cs)
    {
        constraints.set(*cs);
        enable = true;
    }
}

void AcAppIdDebug::execute(Analyzer&)
{
    if (appidDebug)
    {
        if (enable)
            appidDebug->set_constraints("appid", &constraints);
        else
            appidDebug->set_constraints("appid", nullptr);
    }
    // FIXIT-L Add a warning if command was called without appid configured?
}

static int enable_debug(lua_State* L)
{
    int proto = luaL_optint(L, 1, 0);
    const char* sipstr = luaL_optstring(L, 2, nullptr);
    int sport = luaL_optint(L, 3, 0);
    const char* dipstr = luaL_optstring(L, 4, nullptr);
    int dport = luaL_optint(L, 5, 0);

    AppIdDebugSessionConstraints constraints = { };
    if (sipstr)
    {
        if (constraints.sip.set(sipstr) != SFIP_SUCCESS)
            LogMessage("Invalid source IP address provided: %s\n", sipstr);
        else if (constraints.sip.is_set())
            constraints.sip_flag = true;
    }

    if (dipstr)
    {
        if (constraints.dip.set(dipstr) != SFIP_SUCCESS)
            LogMessage("Invalid destination IP address provided: %s\n", dipstr);
        else if (constraints.dip.is_set())
            constraints.dip_flag = true;
    }

    if (proto)
        constraints.protocol = (IpProtocol) proto;

    constraints.sport = sport;
    constraints.dport = dport;

    main_broadcast_command(new AcAppIdDebug(&constraints), true);

    return 0;
}

static int disable_debug(lua_State*)
{
    main_broadcast_command(new AcAppIdDebug(nullptr), true);
    return 0;
}

static const Parameter enable_debug_params[] =
{
    { "proto", Parameter::PT_INT, nullptr, nullptr, "numerical IP protocol ID filter" },
    { "src_ip", Parameter::PT_STRING, nullptr, nullptr, "source IP address filter" },
    { "src_port", Parameter::PT_INT, nullptr, nullptr, "source port filter" },
    { "dst_ip", Parameter::PT_STRING, nullptr, nullptr, "destination IP address filter" },
    { "dst_port", Parameter::PT_INT, nullptr, nullptr, "destination port filter" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Command appid_cmds[] =
{
    { "enable_debug", enable_debug, enable_debug_params, "enable appid debugging"},
    { "disable_debug", disable_debug, nullptr, "disable appid debugging"},
    { nullptr, nullptr, nullptr, nullptr }
};

//  FIXIT-M Add appid_rules back in once we start using it.
#ifdef REMOVED_WHILE_NOT_IN_USE
static const RuleMap appid_rules[] =
{
    { 0 /* rule id */, "description" },
    { 0, nullptr }
};
#endif

static const PegInfo appid_pegs[] =
{
    { CountType::SUM, "packets", "count of packets received" },
    { CountType::SUM, "processed_packets", "count of packets processed" },
    { CountType::SUM, "ignored_packets", "count of packets ignored" },
    { CountType::SUM, "total_sessions", "count of sessions created" },
    { CountType::SUM, "appid_unknown", "count of sessions where appid could not be determined" },
    { CountType::END, nullptr, nullptr},
};

AppIdModule::AppIdModule() :
    Module(MOD_NAME, MOD_HELP, s_params, false, &TRACE_NAME(appid_module))
{
    config = nullptr;
}

AppIdModule::~AppIdModule()
{
    AppIdPegCounts::cleanup_peg_info();
}

ProfileStats* AppIdModule::get_profile() const
{
    return &appidPerfStats;
}

const AppIdModuleConfig* AppIdModule::get_data()
{
    AppIdModuleConfig* temp = config;
    config = nullptr;
    return temp;
}

bool AppIdModule::set(const char* fqn, Value& v, SnortConfig* c)
{
#ifdef USE_RNA_CONFIG
    if ( v.is("conf") )
        config->conf_file = snort_strdup(v.get_string());
    else
#endif
    // FIXIT-L: DECRYPT_DEBUG - Move this to ssl-module
#ifdef REG_TEST
    if ( v.is("first_decrypted_packet_debug") )
        config->first_decrypted_packet_debug = v.get_long();
    else
#endif
    if ( v.is("memcap") )
        config->memcap = v.get_long();
    else if ( v.is("log_stats") )
        config->stats_logging_enabled = v.get_bool();
    else if ( v.is("app_stats_period") )
        config->app_stats_period = v.get_long();
    else if ( v.is("app_stats_rollover_size") )
        config->app_stats_rollover_size = v.get_long();
    else if ( v.is("app_stats_rollover_time") )
        config->app_stats_rollover_time = v.get_long();
    else if ( v.is("app_detector_dir") )
        config->app_detector_dir = snort_strdup(v.get_string());
    else if ( v.is("tp_appid_path") )
        config->tp_appid_path = std::string(v.get_string());
    else if ( v.is("tp_appid_config") )
        config->tp_appid_config = std::string(v.get_string());
    else if ( v.is("instance_id") )
        config->instance_id = v.get_long();
    else if ( v.is("debug") )
        config->debug = v.get_bool();
    else if ( v.is("dump_ports") )
        config->dump_ports = v.get_bool();
    else if ( v.is("log_all_sessions") )
        config->log_all_sessions = v.get_bool();
    else
        return Module::set(fqn, v, c);

    return true;
}

bool AppIdModule::begin(const char* /*fqn*/, int, SnortConfig*)
{
    if ( config )
        return false;

    config = new AppIdModuleConfig;
    return true;
}

bool AppIdModule::end(const char*, int, SnortConfig*)
{
    assert(config);

    if ( !config->app_detector_dir )
    {
        ParseWarning(WARN_CONF,
            "appid: app_detector_dir not configured; no support for appids in rules.\n");
    }
    return true;
}

const Command* AppIdModule::get_commands() const
{
    return appid_cmds;
}

const PegInfo* AppIdModule::get_pegs() const
{
    return appid_pegs;
}

PegCount* AppIdModule::get_counts() const
{
    return (PegCount*)&appid_stats;
}

void AppIdModule::sum_stats(bool accumulate_now_stats)
{
    AppIdPegCounts::sum_stats();
    Module::sum_stats(accumulate_now_stats);
}

void AppIdModule::show_dynamic_stats()
{
    AppIdPegCounts::print();
}
