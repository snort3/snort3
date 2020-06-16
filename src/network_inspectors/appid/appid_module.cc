//--------------------------------------------------------------------------
// Copyright (C) 2016-2020 Cisco and/or its affiliates. All rights reserved.
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
#include "main/snort.h"
#include "main/swapper.h"
#include "main/thread_config.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler.h"
#include "src/main.h"
#include "trace/trace.h"
#include "utils/util.h"

#include "app_info_table.h"
#include "appid_debug.h"
#include "appid_inspector.h"
#include "appid_peg_counts.h"
#include "service_state.h"

using namespace snort;
using namespace std;

THREAD_LOCAL const Trace* appid_trace = nullptr;

//-------------------------------------------------------------------------
// appid module
//-------------------------------------------------------------------------

THREAD_LOCAL ProfileStats appid_perf_stats;
THREAD_LOCAL AppIdStats appid_stats;

static const Parameter s_params[] =
{
    // FIXIT-L: DECRYPT_DEBUG - Move this to ssl-module
#ifdef REG_TEST
    { "first_decrypted_packet_debug", Parameter::PT_INT, "0:max32", "0",
      "the first packet of an already decrypted SSL flow (debug single session only)" },
#endif
    { "memcap", Parameter::PT_INT, "1024:maxSZ", "1048576",
      "max size of the service cache before we start pruning the cache" },
    { "log_stats", Parameter::PT_BOOL, nullptr, "false",
      "enable logging of appid statistics" },
    { "app_stats_period", Parameter::PT_INT, "1:max32", "300",
      "time period for collecting and logging appid statistics" },
    { "app_stats_rollover_size", Parameter::PT_INT, "0:max32", "20971520",
      "max file size for appid stats before rolling over the log file" },
    { "app_detector_dir", Parameter::PT_STRING, nullptr, nullptr,
      "directory to load appid detectors from" },
    { "list_odp_detectors", Parameter::PT_BOOL, nullptr, "false",
      "enable logging of odp detectors statistics" },
    { "tp_appid_path", Parameter::PT_STRING, nullptr, nullptr,
      "path to third party appid dynamic library" },
    { "tp_appid_config", Parameter::PT_STRING, nullptr, nullptr,
      "path to third party appid configuration file" },
    { "tp_appid_stats_enable", Parameter::PT_BOOL, nullptr, nullptr,
      "enable collection of stats and print stats on exit in third party module" },
    { "tp_appid_config_dump", Parameter::PT_BOOL, nullptr, nullptr,
      "print third party configuration on startup" },
    { "log_all_sessions", Parameter::PT_BOOL, nullptr, "false",
      "enable logging of all appid sessions" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class AcAppIdDebug : public AnalyzerCommand
{
public:
    AcAppIdDebug(AppIdDebugSessionConstraints* cs);
    bool execute(Analyzer&, void**) override;
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

bool AcAppIdDebug::execute(Analyzer&, void**)
{
    if (appidDebug)
    {
        if (enable)
            appidDebug->set_constraints("appid", &constraints);
        else
            appidDebug->set_constraints("appid", nullptr);
    }
    // FIXIT-L Add a warning if command was called without appid configured?

    return true;
}

class ACThirdPartyAppIdContextSwap : public AnalyzerCommand
{
public:
    bool execute(Analyzer&, void**) override;
    ACThirdPartyAppIdContextSwap(ThirdPartyAppIdContext* tp_ctxt, Request& current_request,
        bool from_shell): tp_ctxt(tp_ctxt),request(current_request),
        from_shell(from_shell) { }
    ~ACThirdPartyAppIdContextSwap() override;
    const char* stringify() override { return "THIRD-PARTY_CONTEXT_SWAP"; }
private:
    ThirdPartyAppIdContext* tp_ctxt =  nullptr;
    Request& request;
    bool from_shell;
};

bool ACThirdPartyAppIdContextSwap::execute(Analyzer&, void**)
{
    assert(tp_appid_thread_ctxt);
    AppIdInspector* inspector = (AppIdInspector*) InspectorManager::get_inspector(MOD_NAME);
    assert(inspector);
    ThirdPartyAppIdContext* tp_appid_ctxt = inspector->get_ctxt().get_tp_appid_ctxt();
    assert(tp_appid_thread_ctxt != tp_appid_ctxt);
    request.respond("== swapping third-party configuration\n", from_shell);
    tp_appid_thread_ctxt->tfini();
    tp_appid_ctxt->tinit();
    tp_appid_thread_ctxt = tp_appid_ctxt;

    return true;
}

ACThirdPartyAppIdContextSwap::~ACThirdPartyAppIdContextSwap()
{
    delete tp_ctxt;
    Swapper::set_reload_in_progress(false);
    LogMessage("== reload third-party complete\n");
    request.respond("== reload third-party complete\n", from_shell, true);
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

static int reload_third_party(lua_State* L)
{
    bool from_shell = ( L != nullptr );
    Request& current_request = get_current_request();
    if (Swapper::get_reload_in_progress())
    {
        current_request.respond("== reload pending; retry\n", from_shell);
        return 0;
    }
    Swapper::set_reload_in_progress(true);
    current_request.respond(".. reloading third-party\n", from_shell);
    AppIdInspector* inspector = (AppIdInspector*) InspectorManager::get_inspector(MOD_NAME);
    if (!inspector)
    {
        current_request.respond("== reload third-party failed - appid not enabled\n", from_shell);
        return 0;
    }
    AppIdContext& ctxt = inspector->get_ctxt();
    ThirdPartyAppIdContext* old_ctxt = ctxt.get_tp_appid_ctxt();
    if (!old_ctxt)
    {
        current_request.respond("== reload third-party failed - third-party module doesn't exist\n", from_shell);
        return 0;
    }
    ctxt.create_tp_appid_ctxt();
    main_broadcast_command(new ACThirdPartyAppIdContextSwap(old_ctxt, current_request, from_shell), from_shell);
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
    { "reload_third_party", reload_third_party, nullptr, "reload appid third-party module" },
    { nullptr, nullptr, nullptr, nullptr }
};

static const PegInfo appid_pegs[] =
{
    { CountType::SUM, "packets", "count of packets received" },
    { CountType::SUM, "processed_packets", "count of packets processed" },
    { CountType::SUM, "ignored_packets", "count of packets ignored" },
    { CountType::SUM, "total_sessions", "count of sessions created" },
    { CountType::SUM, "appid_unknown", "count of sessions where appid could not be determined" },
    { CountType::SUM, "service_cache_prunes", "number of times the service cache was pruned" },
    { CountType::SUM, "service_cache_adds", "number of times an entry was added to the service cache" },
    { CountType::SUM, "service_cache_removes", "number of times an item was removed from the service cache" },
    { CountType::END, nullptr, nullptr },
};

AppIdModule::AppIdModule() : Module(MOD_NAME, MOD_HELP, s_params)
{
    config = nullptr;
}

AppIdModule::~AppIdModule()
{
    AppIdPegCounts::cleanup_peg_info();
}

void AppIdModule::set_trace(const Trace* trace) const
{ appid_trace = trace; }

const TraceOption* AppIdModule::get_trace_options() const
{
    static const TraceOption appid_trace_options(nullptr, 0, nullptr);
    return &appid_trace_options;
}

ProfileStats* AppIdModule::get_profile() const
{
    return &appid_perf_stats;
}

const AppIdConfig* AppIdModule::get_data()
{
    AppIdConfig* temp = config;
    config = nullptr;
    return temp;
}

bool AppIdModule::set(const char*, Value& v, SnortConfig*)
{
    // FIXIT-L: DECRYPT_DEBUG - Move this to ssl-module
#ifdef REG_TEST
    if ( v.is("first_decrypted_packet_debug") )
        config->first_decrypted_packet_debug = v.get_uint32();
    else
#endif
    if ( v.is("memcap") )
        config->memcap = v.get_size();
    else if ( v.is("log_stats") )
        config->log_stats = v.get_bool();
    else if ( v.is("app_stats_period") )
        config->app_stats_period = v.get_uint32();
    else if ( v.is("app_stats_rollover_size") )
        config->app_stats_rollover_size = v.get_uint32();
    else if ( v.is("app_detector_dir") )
        config->app_detector_dir = snort_strdup(v.get_string());
    else if ( v.is("tp_appid_path") )
        config->tp_appid_path = std::string(v.get_string());
    else if ( v.is("tp_appid_config") )
        config->tp_appid_config = std::string(v.get_string());
    else if ( v.is("tp_appid_stats_enable") )
        config->tp_appid_stats_enable = v.get_bool();
    else if ( v.is("tp_appid_config_dump") )
        config->tp_appid_config_dump = v.get_bool();
    else if ( v.is("list_odp_detectors") )
        config->list_odp_detectors = v.get_bool();
    else if ( v.is("log_all_sessions") )
        config->log_all_sessions = v.get_bool();

    return true;
}

bool AppIdModule::begin(const char*, int, SnortConfig*)
{
    if ( config )
        return false;

    config = new AppIdConfig;
    return true;
}

bool AppIdModule::end(const char* fqn, int, SnortConfig* sc)
{
    assert(config);

    if ( strcmp(fqn, "appid") == 0 )
    {
        appid_rrt.memcap = config->memcap;
        if ( Snort::is_reloading() )
            sc->register_reload_resource_tuner(appid_rrt);
    }

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

bool AppIdReloadTuner::tinit()
{
    return AppIdServiceState::initialize(memcap);
}

bool AppIdReloadTuner::tune_resources(unsigned work_limit)
{
    return AppIdServiceState::prune(memcap, work_limit);
}
