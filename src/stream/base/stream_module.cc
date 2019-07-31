//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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
#include "main/snort_debug.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// stream module
//-------------------------------------------------------------------------
Trace TRACE_NAME(stream);

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

FLOW_TYPE_PARAMS(ip_params, "180", "64");
FLOW_TYPE_PARAMS(icmp_params, "180", "8");
FLOW_TYPE_PARAMS(tcp_params, "3600", "11500");
FLOW_TYPE_PARAMS(udp_params, "180", "128");
FLOW_TYPE_PARAMS(user_params,"180", "256");
FLOW_TYPE_PARAMS(file_params, "180", "32");

#define FLOW_TYPE_TABLE(flow_type, proto, params) \
    { flow_type, Parameter::PT_TABLE, params, nullptr, \
      "configure " proto " cache limits" }

static const Parameter s_params[] =
{
    { "footprint", Parameter::PT_INT, "0:max32", "0",
        "use zero for production, non-zero for testing at given size (for TCP and user)" },

    { "ip_frags_only", Parameter::PT_BOOL, nullptr, "false",
            "don't process non-frag flows" },

    { "max_flows", Parameter::PT_INT, "2:max32", "476288",
                "maximum simultaneous flows tracked before pruning" },

    { "pruning_timeout", Parameter::PT_INT, "1:max32", "30",
                    "minimum inactive time before being eligible for pruning" },

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

StreamModule::StreamModule() :
    Module(MOD_NAME, MOD_HELP, s_params, false, &TRACE_NAME(stream))
{ }

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
{
    return &config;
}

bool StreamModule::begin(const char* fqn, int, SnortConfig*)
{
    if ( !strcmp(fqn, MOD_NAME) )
        config = {};

    return true;
}

bool StreamModule::set(const char* fqn, Value& v, SnortConfig* c)
{
    PktType type = PktType::NONE;

    if ( v.is("footprint") )
    {
        config.footprint = v.get_uint32();
        return true;
    }
    else if ( v.is("ip_frags_only") )
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
        return Module::set(fqn, v, c);

    if ( v.is("idle_timeout") )
        config.flow_cache_cfg.proto[to_utype(type)].nominal_timeout = v.get_uint32();
    else if ( v.is("cap_weight") )
        config.flow_cache_cfg.proto[to_utype(type)].cap_weight = v.get_uint16();
    else
        return false;

    return true;
}

static int check_stream_config(const FlowCacheConfig& new_cfg, const FlowCacheConfig& saved_cfg)
{
    int ret = 0;

    if ( saved_cfg.max_flows != new_cfg.max_flows
            or saved_cfg.pruning_timeout != new_cfg.pruning_timeout )
    {
        ReloadError("Change of stream flow cache options requires a restart\n");
        ret = 1;
    }

    return ret;
}

static int check_stream_proto_config(const FlowCacheConfig& new_cfg, const FlowCacheConfig& saved_cfg, PktType type)
{
    int ret = 0;

    if ( saved_cfg.proto[to_utype(type)].nominal_timeout != new_cfg.proto[to_utype(type)].nominal_timeout )
    {
        ReloadError("Change of stream protocol configuration options requires a restart\n");
        ret = 1;
    }

    return ret;
}

// FIXIT-L the detection of stream.xxx_cache changes below is a temporary workaround
// remove this check when stream.xxx_cache params become reloadable
bool StreamModule::end(const char* fqn, int, SnortConfig*)
{
    static StreamModuleConfig saved_config = {};
    static int issue_found = 0;

    if ( saved_config.flow_cache_cfg.max_flows )
    {
        // FIXIT-H - stream reload story will change this to look for change to max_flows config option
        issue_found += check_stream_config(config.flow_cache_cfg, saved_config.flow_cache_cfg);
        issue_found += check_stream_proto_config(config.flow_cache_cfg, saved_config.flow_cache_cfg, PktType::IP);
        issue_found += check_stream_proto_config(config.flow_cache_cfg, saved_config.flow_cache_cfg, PktType::UDP);
        issue_found += check_stream_proto_config(config.flow_cache_cfg, saved_config.flow_cache_cfg, PktType::TCP);
        issue_found += check_stream_proto_config(config.flow_cache_cfg, saved_config.flow_cache_cfg, PktType::ICMP);
        issue_found += check_stream_proto_config(config.flow_cache_cfg, saved_config.flow_cache_cfg, PktType::PDU);
        issue_found += check_stream_proto_config(config.flow_cache_cfg, saved_config.flow_cache_cfg, PktType::FILE);
    }

    if ( !strcmp(fqn, "stream") )
    {
        if ( saved_config.flow_cache_cfg.max_flows   // saved config is valid
            and config.footprint != saved_config.footprint )
        {
            ReloadError("Changing of stream.footprint requires a restart\n");
            issue_found++;
        }
        if ( issue_found == 0 )
            saved_config = config;
        issue_found = 0;
    }

    return true;
}

void StreamModule::sum_stats(bool)
{ base_sum(); }

void StreamModule::show_stats()
{ base_stats(); }

void StreamModule::reset_stats()
{ base_reset(); }

