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

// stream_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_module.h"

#include "control/control.h"
#include "detection/rules.h"
#include "flow/flow_cache.h"
#include "log/messages.h"
#include "lua/lua.h"
#include "main/analyzer_command.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "stream/flush_bucket.h"
#include "stream/tcp/tcp_stream_tracker.h"
#include "time/packet_time.h"
#include "trace/trace.h"
#include "flow/filter_flow_critera.h"

using namespace snort;
using namespace std;

#ifdef DEBUG_MSGS
static const TraceOption stream_trace_options[] =
{
    { "base", TRACE_BASE, "enable base stream trace logging" },
    { "flow", TRACE_FLOW, "enable flow trace logging" },
    { nullptr, 0, nullptr }
};
#endif

THREAD_LOCAL const Trace* stream_trace = nullptr;
static THREAD_LOCAL timeval reload_time { };

//-------------------------------------------------------------------------
// stream module
//-------------------------------------------------------------------------

#define FLOW_TYPE_PARAMS(name, idle) \
static const Parameter name[] = \
{ \
    { "idle_timeout", Parameter::PT_INT, "1:max32", idle, \
      "maximum inactive time before retiring session tracker" }, \
 \
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } \
}

FLOW_TYPE_PARAMS(ip_params, "180");
FLOW_TYPE_PARAMS(icmp_params, "180");
FLOW_TYPE_PARAMS(tcp_params, "3600");
FLOW_TYPE_PARAMS(udp_params, "180");
FLOW_TYPE_PARAMS(user_params,"180");
FLOW_TYPE_PARAMS(file_params, "180");

#define FLOW_TYPE_TABLE(flow_type, proto, params) \
    { flow_type, Parameter::PT_TABLE, params, nullptr, \
      "configure " proto " cache limits" }

static const Parameter s_params[] =
{
#ifdef REG_TEST
    { "footprint", Parameter::PT_INT, "0:max32", "0",
      "use zero for production, non-zero for testing at given size (for TCP and user)" },
#endif

    { "held_packet_timeout", Parameter::PT_INT, "1:max32", "1000",
      "timeout in milliseconds for held packets" },

    { "ip_frags_only", Parameter::PT_BOOL, nullptr, "false",
      "don't process non-frag flows" },

    { "max_flows", Parameter::PT_INT, "2:max32", "476288",
      "maximum simultaneous flows tracked before pruning" },

    { "prune_flows", Parameter::PT_INT, "1:max32", "10",
      "maximum flows to prune at one time" },

    { "pruning_timeout", Parameter::PT_INT, "1:max32", "30",
      "minimum inactive time before being eligible for pruning" },

    { "require_3whs", Parameter::PT_INT, "-1:max31", "-1",
      "don't track midstream TCP sessions after given seconds from start up; -1 tracks all" },

    FLOW_TYPE_TABLE("ip_cache",   "ip",   ip_params),
    FLOW_TYPE_TABLE("icmp_cache", "icmp", icmp_params),
    FLOW_TYPE_TABLE("tcp_cache",  "tcp",  tcp_params),
    FLOW_TYPE_TABLE("udp_cache",  "udp",  udp_params),
    FLOW_TYPE_TABLE("user_cache", "user", user_params),
    FLOW_TYPE_TABLE("file_cache", "file", file_params),

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

// FIXIT-L setup and clear should extend to non-tcp flows as well
static const RuleMap stream_rules[] =
{
    { SESSION_EVENT_SYN_RX, "TCP SYN received" },
    { SESSION_EVENT_SETUP,  "TCP session established" },
    { SESSION_EVENT_CLEAR,  "TCP session cleared" },

    { 0, nullptr }
};

static const char* const flow_type_names[] =
{ "none", "ip_cache", "tcp_cache", "udp_cache", "icmp_cache", "user_cache", "file_cache", "max"};

StreamModule::StreamModule() : Module(MOD_NAME, MOD_HELP, s_params)
{ }

void StreamModule::set_trace(const Trace* trace) const
{ stream_trace = trace; }

const TraceOption* StreamModule::get_trace_options() const
{
#ifndef DEBUG_MSGS
    return nullptr;
#else
    return stream_trace_options;
#endif
}

static int dump_flows(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    PktType proto_type = PktType::NONE;
    Inspector* inspector = InspectorManager::get_inspector("stream", Module::GLOBAL, IT_STREAM);
    if (!inspector)
    {
        LogRespond(ctrlcon, "Dump flows requires stream to be configured\n");
        return -1;
    }
    const char* file_name = luaL_optstring(L, 1, nullptr);
    if (!file_name)
    {
        LogRespond(ctrlcon, "Dump flows requires a file name\n");
        return -1;
    }
    int count = luaL_optint(L, 2, 4);
    if (0 >= count || 100 < count)
    {
        LogRespond(ctrlcon, "Dump flows requires a count value of 1-100\n");
        return -1;
    }
    const char* protocol = luaL_optstring(L, 3, nullptr);
    if (!protocol)
    {
        LogRespond(ctrlcon, "protocol must be a string or convertible to a string\n");
        return -1;
    }
    
    if (protocol[0] != '\0')
    {
        auto proto_it = protocol_to_type.find(protocol);
        if (proto_it == protocol_to_type.end())
        {
            LogRespond(ctrlcon, "valid protocols are IP/TCP/UDP/ICMP\n");
            return -1;
        }
        else
            proto_type = proto_it->second;
    }

    std::string source_ip = luaL_optstring(L, 4, nullptr);
    if (!source_ip.c_str())
    {
        LogRespond(ctrlcon, "source_ip must be a string or convertible to a string\n");
        return -1;
    }
    std::string destination_ip= luaL_optstring(L, 5, nullptr);
    if (!destination_ip.c_str())
    {
        LogRespond(ctrlcon, "destination_ip must be a string or convertible to a string\n");
        return -1;
    }
    int source_port = luaL_optint(L, 6, -1);
    if ( source_port<0 || source_port>65535 )
    {
        LogRespond(ctrlcon, "source_port must be between 0-65535\n");
        return -1;
    }
    int destination_port = luaL_optint(L, 7, -1);
    if ( destination_port<0 || destination_port>65535)
    {
        LogRespond(ctrlcon, "destination_port must be between 0-65535\n");
        return -1;
    }

/*resume count is used to complete the command execution from
uncompleted queue*/
#ifdef REG_TEST
    int resume = luaL_optint(L, 8, -1);
#endif
    DumpFlows* df = new DumpFlows(count, ctrlcon
#ifdef REG_TEST
        , resume
#endif
    );
    SfIp src_ip,src_subnet;
    if (!df->set_ip(source_ip, src_ip, src_subnet))
    {
        LogRespond(ctrlcon, "Invalid source ip\n");
        delete df;
        return -1;
    }
    SfIp dst_ip,dst_subnet;
    if (!df->set_ip(destination_ip, dst_ip, dst_subnet))
    {
        LogRespond(ctrlcon, "Invalid destination ip\n");
        delete df;
        return -1;
    }

    FilterFlowCriteria ffc;
    ffc.pkt_type = proto_type;
    ffc.source_port = static_cast<uint16_t>(source_port);
    ffc.destination_port = static_cast<uint16_t>(destination_port);
    ffc.source_sfip=src_ip;
    ffc.destination_sfip=dst_ip;
    ffc.source_subnet_sfip=src_subnet;
    ffc.destination_subnet_sfip=dst_subnet;
    df->set_filter_criteria(ffc);

    if (!df->open_files(file_name))
    {
        delete df;
        return -1;
    }

    LogRespond(ctrlcon, "== dumping connections\n");
    main_broadcast_command(df, ctrlcon);
    return 0;
}

static const Command stream_cmds[] =
{
    { "dump_flows", dump_flows, nullptr, "dump the flow table" },

    { nullptr, nullptr, nullptr, nullptr }
};

const snort::Command* StreamModule::get_commands() const
{ return stream_cmds; }

const PegInfo* StreamModule::get_pegs() const
{ return base_pegs; }

PegCount* StreamModule::get_counts() const
{ return (PegCount*)&stream_base_stats; }

ProfileStats* StreamModule::get_profile() const
{ return &s5PerfStats; }

unsigned StreamModule::get_gid() const
{ return GID_SESSION; }

const RuleMap* StreamModule::get_rules() const
{ return stream_rules; }

const StreamModuleConfig* StreamModule::get_data()
{ return &config; }

bool StreamModule::begin(const char* fqn, int, SnortConfig*)
{
    if ( !strcmp(fqn, MOD_NAME) )
        config = {};

    return true;
}

bool StreamModule::set(const char* fqn, Value& v, SnortConfig* c)
{
#ifdef REG_TEST
    if ( v.is("footprint") )
        config.footprint = v.get_uint32();
    else
#endif

    if ( v.is("held_packet_timeout") )
        config.held_packet_timeout = v.get_uint32();

    else if ( v.is("ip_frags_only") )
    {
        if ( v.get_bool() )
            c->set_run_flags(RUN_FLAG__IP_FRAGS_ONLY);
    }
    else if ( v.is("max_flows") )
        config.flow_cache_cfg.max_flows = v.get_uint32();

    else if ( v.is("prune_flows") )
        config.flow_cache_cfg.prune_flows = v.get_uint32();

    else if ( v.is("pruning_timeout") )
        config.flow_cache_cfg.pruning_timeout = v.get_uint32();

    else if ( v.is("require_3whs") )
        config.hs_timeout = v.get_int32();

    else if ( !strcmp(fqn, "stream.file_cache.idle_timeout") )
        config.flow_cache_cfg.proto[to_utype(PktType::FILE)].nominal_timeout = v.get_uint32();

    else if ( !strcmp(fqn, "stream.ip_cache.idle_timeout") )
        config.flow_cache_cfg.proto[to_utype(PktType::IP)].nominal_timeout = v.get_uint32();

    else if ( !strcmp(fqn, "stream.icmp_cache.idle_timeout") )
        config.flow_cache_cfg.proto[to_utype(PktType::ICMP)].nominal_timeout = v.get_uint32();

    else if ( !strcmp(fqn, "stream.tcp_cache.idle_timeout") )
        config.flow_cache_cfg.proto[to_utype(PktType::TCP)].nominal_timeout = v.get_uint32();

    else if ( !strcmp(fqn, "stream.udp_cache.idle_timeout") )
        config.flow_cache_cfg.proto[to_utype(PktType::UDP)].nominal_timeout = v.get_uint32();

    else
    {
        assert(!strcmp(fqn, "stream.user_cache.idle_timeout"));
        config.flow_cache_cfg.proto[to_utype(PktType::USER)].nominal_timeout = v.get_uint32();
    }

    return true;
}

bool StreamModule::end(const char* fqn, int, SnortConfig* sc)
{
    if ( config.hs_timeout != -1 ) // condition required until stream_tcp.require_3whs is removed
        get_network_parse_policy()->hs_timeout = config.hs_timeout;

    if ( Snort::is_reloading() && strcmp(fqn, MOD_NAME) == 0 )
    {
        StreamReloadResourceManager* reload_resource_manager = new StreamReloadResourceManager;
        if (reload_resource_manager->initialize(config))
            sc->register_reload_handler(reload_resource_manager);
        else
            delete reload_resource_manager;

        sc->register_reload_handler(new HPQReloadTuner(config.held_packet_timeout));
    }

    return true;
}

void StreamModule::prep_counts(bool)
{ base_prep(); }

void StreamModule::sum_stats(bool dump_stats)
{
    Module::sum_stats(dump_stats);
    if(!dump_stats)
        base_reset();
}

void StreamModule::reset_stats()
{
    base_reset();
    Module::reset_stats();
}

// Stream handler to adjust allocated resources as needed on a config reload
bool StreamReloadResourceManager::initialize(const StreamModuleConfig& config_)
{
    // saving a copy of the config only works here because there is only
    // one stream inspector per packet thread...
#ifdef REG_TEST
    if ( config.footprint != config_.footprint )
    {
        ReloadError("Changing stream.footprint requires a restart.\n");
        return false;
    }
#endif
    config = config_;
    return true;
}

bool StreamReloadResourceManager::tinit()
{
    int max_flows_change =
        config.flow_cache_cfg.max_flows - flow_con->get_flow_cache_config().max_flows;

    if ( max_flows_change )
    {
        if ( max_flows_change < 0 )
            stream_base_stats.reload_total_deletes += abs(max_flows_change);
        else
            stream_base_stats.reload_total_adds += max_flows_change;

        flow_con->set_flow_cache_config(config.flow_cache_cfg);
        return true;
    }

    return false;
}

bool StreamReloadResourceManager::tune_packet_context()
{
    ++stream_base_stats.reload_tuning_packets;
    return tune_resources(max_work);
}

bool StreamReloadResourceManager::tune_idle_context()
{
    ++stream_base_stats.reload_tuning_idle;
    return tune_resources(max_work_idle);
}

bool StreamReloadResourceManager::tune_resources(unsigned work_limit)
{
    // we are done if new max is > currently allocated flow objects
    if ( flow_con->get_flows_allocated() <= config.flow_cache_cfg.max_flows )
        return true;

    unsigned flows_to_delete =
        flow_con->get_flows_allocated() - config.flow_cache_cfg.max_flows;
    if ( flows_to_delete > work_limit )
        flows_to_delete -= flow_con->delete_flows(work_limit);
    else
        flows_to_delete -= flow_con->delete_flows(flows_to_delete);

    return ( flows_to_delete ) ? false : true;
}

bool StreamUnloadReloadResourceManager::tinit()
{
    unsigned max_flows = flow_con->get_flow_cache_config().max_flows;
    if (max_flows)
    {
        stream_base_stats.reload_total_deletes += max_flows;
        return true;
    }
    return false;
}

bool StreamUnloadReloadResourceManager::tune_packet_context()
{
    ++stream_base_stats.reload_tuning_packets;
    return tune_resources(max_work);
}

bool StreamUnloadReloadResourceManager::tune_idle_context()
{
    ++stream_base_stats.reload_tuning_idle;
    return tune_resources(max_work_idle);
}

bool StreamUnloadReloadResourceManager::tune_resources(unsigned work_limit)
{
    unsigned flows_to_delete = flow_con->get_flows_allocated();

    if (!flows_to_delete)
        return true;

    if (flows_to_delete > work_limit)
        flows_to_delete -= flow_con->delete_flows(work_limit);
    else
        flows_to_delete -= flow_con->delete_flows(flows_to_delete);

    return (flows_to_delete) ? false : true;
}

void StreamModuleConfig::show() const
{
    ConfigLogger::log_value("max_flows", flow_cache_cfg.max_flows);
    ConfigLogger::log_value("max_aux_ip", SnortConfig::get_conf()->max_aux_ip);
    ConfigLogger::log_value("pruning_timeout", flow_cache_cfg.pruning_timeout);
    ConfigLogger::log_value("prune_flows", flow_cache_cfg.prune_flows);
    ConfigLogger::log_limit("require_3whs", hs_timeout, -1, hs_timeout < 0 ? hs_timeout : -1);

    for (int i = to_utype(PktType::IP); i < to_utype(PktType::PDU); ++i)
    {
        std::string tmp;
        tmp += "{ idle_timeout = " + std::to_string(flow_cache_cfg.proto[i].nominal_timeout);
        tmp += " }";

        ConfigLogger::log_value(flow_type_names[i], tmp.c_str());
    }
}

bool HPQReloadTuner::tinit()
{
    packet_gettimeofday(&reload_time);
    return TcpStreamTracker::adjust_expiration(held_packet_timeout, reload_time);
}

bool HPQReloadTuner::tune_packet_context()
{
    return !TcpStreamTracker::release_held_packets(reload_time, max_work);
}

bool HPQReloadTuner::tune_idle_context()
{
    return !TcpStreamTracker::release_held_packets(reload_time, max_work_idle);
}
