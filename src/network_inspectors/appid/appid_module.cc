//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "control/control.h"
#include "host_tracker/host_cache.h"
#include "log/messages.h"
#include "main/analyzer.h"
#include "main/analyzer_command.h"
#include "main/reload_tracker.h"
#include "main/snort.h"
#include "main/swapper.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler.h"
#include "pub_sub/appid_debug_log_event.h"
#include "src/main.h"
#include "target_based/host_attributes.h"
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
THREAD_LOCAL bool ThirdPartyAppIdContext::tp_reload_in_progress = false;

static const Parameter s_params[] =
{
    // FIXIT-L: DECRYPT_DEBUG - Move this to ssl-module
#ifdef REG_TEST
    { "first_decrypted_packet_debug", Parameter::PT_INT, "0:max32", "0",
      "the first packet of an already decrypted SSL flow (debug single session only)" },
    { "log_eve_process_client_mappings", Parameter::PT_BOOL, nullptr, "false",
      "enable logging of encrypted visibility engine process to client mappings" },
    { "log_alpn_service_mappings", Parameter::PT_BOOL, nullptr, "false",
      "enable logging of alpn service mappings" },
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
    { "enable_rna_filter", Parameter::PT_BOOL, nullptr, "false",
      "monitor only the networks specified in rna configuration" },
    { "rna_conf_path", Parameter::PT_STRING, nullptr, nullptr,
      "path to rna configuration file" },
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
        constraints = *cs;
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

bool ACThirdPartyAppIdCleanup::execute(Analyzer& a, void**)
{
    if (!pkt_thread_tp_appid_ctxt)
        return true;
    bool tear_down_in_progress;
    if (a.is_idling())
        tear_down_in_progress = pkt_thread_tp_appid_ctxt->tfini(true);
    else
        tear_down_in_progress = pkt_thread_tp_appid_ctxt->tfini();
    return !tear_down_in_progress;
}

class ACThirdPartyAppIdContextSwap : public AnalyzerCommand
{
public:
    bool execute(Analyzer&, void**) override;
    ACThirdPartyAppIdContextSwap(const AppIdInspector& inspector, ControlConn* conn)
        : AnalyzerCommand(conn), inspector(inspector)
    {
        LogMessage("== swapping third-party configuration\n");
    }

    ~ACThirdPartyAppIdContextSwap() override;
    const char* stringify() override { return "THIRD-PARTY_CONTEXT_SWAP"; }
private:
    const AppIdInspector& inspector;
};

bool ACThirdPartyAppIdContextSwap::execute(Analyzer&, void**)
{
    assert(!pkt_thread_tp_appid_ctxt);
    pkt_thread_tp_appid_ctxt = inspector.get_ctxt().get_tp_appid_ctxt();
    pkt_thread_tp_appid_ctxt->tinit();
    ThirdPartyAppIdContext::set_tp_reload_in_progress(false);

    return true;
}

ACThirdPartyAppIdContextSwap::~ACThirdPartyAppIdContextSwap()
{
    const AppIdContext& ctxt = inspector.get_ctxt();
    std::string file_path = ctxt.get_tp_appid_ctxt()->get_user_config();
    ctxt.get_odp_ctxt().get_app_info_mgr().dump_appid_configurations(file_path);
    log_message("== reload third-party complete\n");
    LogMessage("== third-party configuration swap complete\n");
    ReloadTracker::end(ctrlcon, true);
}

class ACThirdPartyAppIdContextUnload : public AnalyzerCommand
{
public:
    bool execute(Analyzer&, void**) override;
    ACThirdPartyAppIdContextUnload(const AppIdInspector& inspector, ThirdPartyAppIdContext* tp_ctxt,
        ControlConn* conn): AnalyzerCommand(conn), inspector(inspector), tp_ctxt(tp_ctxt)
    { }
    ~ACThirdPartyAppIdContextUnload() override;
    const char* stringify() override { return "THIRD-PARTY_CONTEXT_UNLOAD"; }
private:
    const AppIdInspector& inspector;
    ThirdPartyAppIdContext* tp_ctxt =  nullptr;
};

bool ACThirdPartyAppIdContextUnload::execute(Analyzer& ac, void**)
{
    assert(pkt_thread_tp_appid_ctxt);
    ThirdPartyAppIdContext::set_tp_reload_in_progress(true);
    bool reload_in_progress;
    if (ac.is_idling())
        reload_in_progress = pkt_thread_tp_appid_ctxt->tfini(true);
    else
        reload_in_progress = pkt_thread_tp_appid_ctxt->tfini();
    if (reload_in_progress)
        return false;
    pkt_thread_tp_appid_ctxt = nullptr;

    return true;
}

ACThirdPartyAppIdContextUnload::~ACThirdPartyAppIdContextUnload()
{
    delete tp_ctxt;
    AppIdContext& ctxt = inspector.get_ctxt();
    ctxt.create_tp_appid_ctxt();
    main_broadcast_command(new ACThirdPartyAppIdContextSwap(inspector, ctrlcon));
    log_message("== unload old third-party complete\n");
    ReloadTracker::update(ctrlcon, "unload old third-party complete, start swapping to new configuration.");
}

class ACOdpContextSwap : public AnalyzerCommand
{
public:
    bool execute(Analyzer&, void**) override;
    ACOdpContextSwap(const AppIdInspector& inspector, OdpContext& odp_ctxt, ControlConn* conn) :
        AnalyzerCommand(conn), inspector(inspector), odp_ctxt(odp_ctxt)
    { }
    ~ACOdpContextSwap() override;
    const char* stringify() override { return "ODP_CONTEXT_SWAP"; }
private:
    const AppIdInspector& inspector;
    OdpContext& odp_ctxt;
};

bool ACOdpContextSwap::execute(Analyzer&, void**)
{
    AppIdContext& ctxt = inspector.get_ctxt();
    OdpContext& current_odp_ctxt = ctxt.get_odp_ctxt();
    assert(pkt_thread_odp_ctxt != &current_odp_ctxt);

    HostAttributesManager::clear_appid_services();
    AppIdServiceState::clean();
    AppIdPegCounts::cleanup_pegs();
    AppIdServiceState::initialize(ctxt.config.memcap);
    AppIdPegCounts::init_pegs();

    pkt_thread_odp_ctxt = &current_odp_ctxt;
    assert(odp_thread_local_ctxt);
    delete odp_thread_local_ctxt;
    odp_thread_local_ctxt = new OdpThreadContext;
    odp_thread_local_ctxt->initialize(SnortConfig::get_conf(), ctxt, false, true);
    return true;
}

ACOdpContextSwap::~ACOdpContextSwap()
{
    odp_ctxt.get_app_info_mgr().cleanup_appid_info_table();
    delete &odp_ctxt;
    AppIdContext& ctxt = inspector.get_ctxt();
    if (ctxt.config.app_detector_dir)
    {
        std::string file_path = std::string(ctxt.config.app_detector_dir) + "/custom/userappid.conf";
        if (access(file_path.c_str(), F_OK))
            file_path = std::string(ctxt.config.app_detector_dir) + "/../userappid.conf";
        ctxt.get_odp_ctxt().get_app_info_mgr().dump_appid_configurations(file_path);
    }
    SnortConfig::get_main_conf()->update_scratch(ctrlcon);
    log_message("== reload detectors complete\n");
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

    AppIdDebugLogEvent event(&constraints, "AppIdDbg");
    DataBus::publish(AppIdInspector::get_pub_id(), AppIdEventIds::DEBUG_LOG, event);

    main_broadcast_command(new AcAppIdDebug(&constraints), ControlConn::query_from_lua(L));

    return 0;
}

static int disable_debug(lua_State* L)
{
    AppIdDebugLogEvent event(nullptr, "");
    DataBus::publish(AppIdInspector::get_pub_id(), AppIdEventIds::DEBUG_LOG, event);
    main_broadcast_command(new AcAppIdDebug(nullptr), ControlConn::query_from_lua(L));
    return 0;
}

static int reload_third_party(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    if (!ReloadTracker::start(ctrlcon))
    {
        ctrlcon->respond("== reload pending; retry\n");
        return 0;
    }

    AppIdInspector* inspector = (AppIdInspector*) InspectorManager::get_inspector(MOD_NAME);
    if (!inspector)
    {
        ReloadTracker::failed(ctrlcon, "appid not enabled");
        ctrlcon->respond("== reload third-party failed - appid not enabled\n");
        return 0;
    }
    const AppIdContext& ctxt = inspector->get_ctxt();
    ThirdPartyAppIdContext* old_ctxt = ctxt.get_tp_appid_ctxt();
    if (!old_ctxt)
    {
        ReloadTracker::failed(ctrlcon, "third-party module doesn't exist");
        ctrlcon->respond("== reload third-party failed - third-party module doesn't exist\n");
        return 0;
    }

    ReloadTracker::update(ctrlcon, "unloading old third-party configuration");
    ctrlcon->respond("== unloading old third-party configuration\n");
    main_broadcast_command(new ACThirdPartyAppIdContextUnload(*inspector, old_ctxt, ctrlcon), ctrlcon);
    return 0;
}

static void clear_dynamic_host_cache_services()
{
    auto hosts = host_cache.get_all_data();
    for ( auto& h : hosts )
    {
        h.second->remove_inferred_services();
    }
}

static int reload_detectors(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    if ( !ReloadTracker::start(ctrlcon) )
    {
        ctrlcon->respond("== reload pending; retry\n");
        return 0;
    }
    AppIdInspector* inspector = (AppIdInspector*) InspectorManager::get_inspector(MOD_NAME);
    if (!inspector)
    {
        ctrlcon->respond("== reload detectors failed - appid not enabled\n");
        ReloadTracker::failed(ctrlcon, "appid not enabled");
        return 0;
    }

    ctrlcon->respond(".. reloading detectors\n");

    AppIdContext& ctxt = inspector->get_ctxt();
    OdpContext& old_odp_ctxt = ctxt.get_odp_ctxt();
    ServiceDiscovery::clear_ftp_service_state();
    clear_dynamic_host_cache_services();
    AppIdPegCounts::cleanup_peg_info();
    LuaDetectorManager::clear_lua_detector_mgrs();
    ctxt.create_odp_ctxt();
    assert(odp_thread_local_ctxt);
    delete odp_thread_local_ctxt;
    odp_thread_local_ctxt = new OdpThreadContext;

    OdpContext& odp_ctxt = ctxt.get_odp_ctxt();
    odp_ctxt.get_client_disco_mgr().initialize(*inspector);
    odp_ctxt.get_service_disco_mgr().initialize(*inspector);
    odp_thread_local_ctxt->initialize(SnortConfig::get_conf(), ctxt, true, true);
    odp_ctxt.initialize(*inspector);

    ctrlcon->respond("== swapping detectors configuration\n");
    ReloadTracker::update(ctrlcon, "swapping detectors configuration");
    main_broadcast_command(new ACOdpContextSwap(*inspector, old_odp_ctxt, ctrlcon), ctrlcon);
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
    { "reload_detectors", reload_detectors, nullptr, "reload appid detectors" },
    { nullptr, nullptr, nullptr, nullptr }
};

static const PegInfo appid_pegs[] =
{
    { CountType::SUM, "packets", "count of packets received" },
    { CountType::SUM, "processed_packets", "count of packets processed" },
    { CountType::SUM, "ignored_packets", "count of packets ignored" },
    { CountType::SUM, "total_sessions", "count of sessions created" },
    { CountType::SUM, "service_cache_prunes", "number of times the service cache was pruned" },
    { CountType::SUM, "service_cache_adds", "number of times an entry was added to the service cache" },
    { CountType::SUM, "service_cache_removes", "number of times an item was removed from the service cache" },
    { CountType::SUM, "odp_reload_ignored_pkts", "count of packets ignored after open detector package is reloaded" },
    { CountType::SUM, "tp_reload_ignored_pkts", "count of packets ignored after third-party module is reloaded" },
    { CountType::NOW, "bytes_in_use", "number of bytes in use in the cache" },
    { CountType::NOW, "items_in_use", "items in use in the cache" },
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
#ifndef DEBUG_MSGS
    return nullptr;
#else
    static const TraceOption appid_trace_options(nullptr, 0, nullptr);
    return &appid_trace_options;
#endif
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
    else if ( v.is("log_eve_process_client_mappings") )
        config->log_eve_process_client_mappings = v.get_bool();
    else if (v.is("log_alpn_service_mappings") )
        config->log_alpn_service_mappings = v.get_bool();
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
    else if ( v.is("enable_rna_filter") )
        config->enable_rna_filter = v.get_bool();
    else if ( v.is("rna_conf_path") )
        config->rna_conf_path = std::string(v.get_string());

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

    if ( Snort::is_reloading() && strcmp(fqn, "appid") == 0 )
        sc->register_reload_handler(new AppIdReloadTuner(config->memcap));

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

void AppIdModule::reset_stats()
{
    AppIdPegCounts::cleanup_dynamic_sum();
    Module::reset_stats();
}

bool AppIdReloadTuner::tinit()
{
    return AppIdServiceState::initialize(memcap);
}

bool AppIdReloadTuner::tune_resources(unsigned work_limit)
{
    return AppIdServiceState::prune(memcap, work_limit);
}
