//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/rules.h"
#include "log/messages.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "stream/flush_bucket.h"
#include "stream/tcp/tcp_stream_tracker.h"
#include "time/packet_time.h"
#include "trace/trace.h"

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

#define FLOW_TYPE_PARAMS(name, idle, weight) \
static const Parameter name[] = \
{ \
    { "idle_timeout", Parameter::PT_INT, "1:max32", idle, \
      "maximum inactive time before retiring session tracker" }, \
 \
    { "cap_weight", Parameter::PT_INT, "0:65535", weight, \
      "additional bytes to track per flow for better estimation against cap" }, \
 \
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } \
}

FLOW_TYPE_PARAMS(ip_params, "180", "0");
FLOW_TYPE_PARAMS(icmp_params, "180", "0");
FLOW_TYPE_PARAMS(tcp_params, "3600", "11000");
FLOW_TYPE_PARAMS(udp_params, "180", "0");
FLOW_TYPE_PARAMS(user_params,"180", "0");
FLOW_TYPE_PARAMS(file_params, "180", "32");

#define FLOW_TYPE_TABLE(flow_type, proto, params) \
    { flow_type, Parameter::PT_TABLE, params, nullptr, \
      "configure " proto " cache limits" }

static const Parameter s_params[] =
{
#ifdef REG_TEST
    { "footprint", Parameter::PT_INT, "0:max32", "0",
      "use zero for production, non-zero for testing at given size (for TCP and user)" },
#endif

    { "ip_frags_only", Parameter::PT_BOOL, nullptr, "false",
      "don't process non-frag flows" },

    { "max_flows", Parameter::PT_INT, "2:max32", "476288",
      "maximum simultaneous flows tracked before pruning" },

    { "pruning_timeout", Parameter::PT_INT, "1:max32", "30",
      "minimum inactive time before being eligible for pruning" },

    { "held_packet_timeout", Parameter::PT_INT, "1:max32", "1000",
      "timeout in milliseconds for held packets" },

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
    PktType type = PktType::NONE;

#ifdef REG_TEST
    if ( v.is("footprint") )
    {
        config.footprint = v.get_uint32();
        return true;
    }
#endif

    if ( v.is("ip_frags_only") )
    {
        if ( v.get_bool() )
            c->set_run_flags(RUN_FLAG__IP_FRAGS_ONLY);
        return true;
    }
    else if ( v.is("max_flows") )
    {
        config.flow_cache_cfg.max_flows = v.get_uint32();
        return true;
    }
    else if ( v.is("pruning_timeout") )
    {
        config.flow_cache_cfg.pruning_timeout = v.get_uint32();
        return true;
    }
    else if ( v.is("held_packet_timeout") )
    {
        config.held_packet_timeout = v.get_uint32();
        return true;
    }
    else if ( strstr(fqn, "ip_cache") )
        type = PktType::IP;
    else if ( strstr(fqn, "icmp_cache") )
        type = PktType::ICMP;
    else if ( strstr(fqn, "tcp_cache") )
        type = PktType::TCP;
    else if ( strstr(fqn, "udp_cache") )
        type = PktType::UDP;
    else if ( strstr(fqn, "user_cache") )
        type = PktType::PDU;
    else if ( strstr(fqn, "file_cache") )
        type = PktType::FILE;
    else
        return false;

    if ( v.is("idle_timeout") )
        config.flow_cache_cfg.proto[to_utype(type)].nominal_timeout = v.get_uint32();

    else if ( v.is("cap_weight") )
        config.flow_cache_cfg.proto[to_utype(type)].cap_weight = v.get_uint16();

    return true;
}

bool StreamModule::end(const char* fqn, int, SnortConfig* sc)
{
    if ( Snort::is_reloading() && strcmp(fqn, MOD_NAME) == 0 )
    {
        StreamReloadResourceManager* reload_resource_manager = new StreamReloadResourceManager;
        if (reload_resource_manager->initialize(config))
            sc->register_reload_resource_tuner(reload_resource_manager);
        else
            delete reload_resource_manager;

        sc->register_reload_resource_tuner(new HPQReloadTuner(config.held_packet_timeout));
    }

    return true;
}

void StreamModule::prep_counts()
{ base_prep(); }

void StreamModule::sum_stats(bool)
{ base_sum(); }

void StreamModule::show_stats()
{ base_stats(); }

void StreamModule::reset_stats()
{ base_reset(); }

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

    for (int i = to_utype(PktType::IP); i < to_utype(PktType::MAX); ++i)
    {
        std::string tmp;
        tmp += "{ idle_timeout = " + std::to_string(flow_cache_cfg.proto[i].nominal_timeout);
        tmp += ", cap_weight = " + std::to_string(flow_cache_cfg.proto[i].cap_weight);
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
