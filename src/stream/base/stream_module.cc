//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
#include "main/snort_debug.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// stream module
//-------------------------------------------------------------------------
Trace TRACE_NAME(stream);

#define CACHE_PARAMS(name, max, prune, idle, cleanup) \
static const Parameter name[] = \
{ \
    { "max_sessions", Parameter::PT_INT, "2:", max, \
      "maximum simultaneous sessions tracked before pruning" }, \
 \
    { "pruning_timeout", Parameter::PT_INT, "1:", prune, \
      "minimum inactive time before being eligible for pruning" }, \
 \
    { "idle_timeout", Parameter::PT_INT, "1:", idle, \
      "maximum inactive time before retiring session tracker" }, \
 \
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } \
}

CACHE_PARAMS(ip_params,    "16384",  "30",  "180", "5");
CACHE_PARAMS(icmp_params,  "65536",  "30",  "180", "5");
CACHE_PARAMS(tcp_params,  "262144",  "30", "3600", "5");
CACHE_PARAMS(udp_params,  "131072",  "30",  "180", "5");
CACHE_PARAMS(user_params,   "1024",  "30",  "180", "5");
CACHE_PARAMS(file_params,    "128",  "30",  "180", "5");

#define CACHE_TABLE(cache, proto, params) \
    { cache, Parameter::PT_TABLE, params, nullptr, \
      "configure " proto " cache limits" }

static const Parameter s_params[] =
{
    { "footprint", Parameter::PT_INT, "0:", "0",
      "use zero for production, non-zero for testing at given size (for TCP and user)" },

    { "ip_frags_only", Parameter::PT_BOOL, nullptr, "false",
      "don't process non-frag flows" },

    CACHE_TABLE("ip_cache",   "ip",   ip_params),
    CACHE_TABLE("icmp_cache", "icmp", icmp_params),
    CACHE_TABLE("tcp_cache",  "tcp",  tcp_params),
    CACHE_TABLE("udp_cache",  "udp",  udp_params),
    CACHE_TABLE("user_cache", "user", user_params),
    CACHE_TABLE("file_cache", "file", file_params),

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
        memset(&config, 0, sizeof(config));

    return true;
}

bool StreamModule::set(const char* fqn, Value& v, SnortConfig* c)
{
    FlowConfig* fc = nullptr;

    if ( v.is("footprint") )
    {
        config.footprint = v.get_long();
        return true;
    }
    else if ( v.is("ip_frags_only") )
    {
        config.ip_frags_only = v.get_bool();
        return true;
    }
    else if ( strstr(fqn, "ip_cache") )
        fc = &config.ip_cfg;

    else if ( strstr(fqn, "icmp_cache") )
        fc = &config.icmp_cfg;

    else if ( strstr(fqn, "tcp_cache") )
        fc = &config.tcp_cfg;

    else if ( strstr(fqn, "udp_cache") )
        fc = &config.udp_cfg;

    else if ( strstr(fqn, "user_cache") )
        fc = &config.user_cfg;

    else if ( strstr(fqn, "file_cache") )
        fc = &config.file_cfg;

    else
        return Module::set(fqn, v, c);

    if ( v.is("max_sessions") )
        fc->max_sessions = v.get_long();

    else if ( v.is("pruning_timeout") )
        fc->pruning_timeout = v.get_long();

    else if ( v.is("idle_timeout") )
        fc->nominal_timeout = v.get_long();

    else
        return false;

    return true;
}

void StreamModule::sum_stats(bool)
{ base_sum(); }

void StreamModule::show_stats()
{ base_stats(); }

void StreamModule::reset_stats()
{ base_reset(); }

