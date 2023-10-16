//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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

// latency_module.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "latency_module.h"

#include <chrono>

#include "main/snort_config.h"
#include "trace/trace.h"

#include "latency_config.h"
#include "latency_rules.h"
#include "latency_stats.h"

using namespace snort;

THREAD_LOCAL const Trace* latency_trace = nullptr;

// -----------------------------------------------------------------------------
// latency attributes
// -----------------------------------------------------------------------------

#define s_name "latency"
#define s_help \
    "packet and rule latency monitoring and control"

static const Parameter s_packet_params[] =
{
    { "max_time", Parameter::PT_INT, "0:max53", "500",
        "set timeout for packet latency thresholding (usec)" },

    { "fastpath", Parameter::PT_BOOL, nullptr, "false",
        "fastpath expensive packets (max_time exceeded)" },

#ifdef REG_TEST
    { "test_timeout", Parameter::PT_BOOL, nullptr, "false",
        "timeout on every packet" },
#endif

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_rule_params[] =
{
    { "max_time", Parameter::PT_INT, "0:max53", "500",
        "set timeout for rule evaluation (usec)" },

    // We could just treat suspend_threshold == 0 as suspend == false
    // but we leave this here for parity with packet latency
    { "suspend", Parameter::PT_BOOL, nullptr, "false",
        "temporarily suspend expensive rules" },

    { "suspend_threshold", Parameter::PT_INT, "1:max32", "5",
        "set threshold for number of timeouts before suspending a rule" },

    { "max_suspend_time", Parameter::PT_INT, "0:max32", "30000",
        "set max time for suspending a rule (ms, 0 means permanently disable rule)" },

#ifdef REG_TEST
    { "test_timeout", Parameter::PT_BOOL, nullptr, "false",
        "timeout on every rule evaluation" },
#endif

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "packet", Parameter::PT_TABLE, s_packet_params, nullptr,
      "packet latency" },

    { "rule", Parameter::PT_TABLE, s_rule_params, nullptr,
      "rule latency" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap latency_rules[] =
{
    { LATENCY_EVENT_RULE_TREE_SUSPENDED, "rule tree suspended due to latency" },
    { LATENCY_EVENT_RULE_TREE_ENABLED, "rule tree re-enabled after suspend timeout" },
    { LATENCY_EVENT_PACKET_FASTPATHED, "packet fastpathed due to latency" },

    { 0, nullptr }
};

THREAD_LOCAL LatencyStats latency_stats;

static const PegInfo latency_pegs[] =
{
    { CountType::SUM, "total_packets", "total packets monitored" },
    { CountType::SUM, "total_usecs", "total usecs elapsed" },
    { CountType::SUM, "max_usecs", "maximum usecs elapsed" },
    { CountType::SUM, "packet_timeouts", "packets that timed out" },
    { CountType::SUM, "total_rule_evals", "total rule evals monitored" },
    { CountType::SUM, "rule_eval_timeouts", "rule evals that timed out" },
    { CountType::SUM, "rule_tree_enables", "rule tree re-enables" },
    { CountType::END, nullptr, nullptr }
};

// -----------------------------------------------------------------------------
// latency module
// -----------------------------------------------------------------------------

static inline bool latency_set(const Value& v, PacketLatencyConfig& config)
{
    if ( v.is("max_time") )
    {
        long t = clock_ticks(v.get_int64());
        config.max_time = TO_DURATION(config.max_time, t);
    }
    else if ( v.is("fastpath") )
        config.fastpath = v.get_bool();
#ifdef REG_TEST
    else if ( v.is("test_timeout") )
        config.test_timeout = v.get_bool();
#endif

    else
        return false;

    return true;
}

static inline bool latency_set(const Value& v, RuleLatencyConfig& config)
{
    if ( v.is("max_time") )
    {
        long t = clock_ticks(v.get_uint64());
        config.max_time = TO_DURATION(config.max_time, t);
    }
    else if ( v.is("suspend") )
        config.suspend = v.get_bool();

    else if ( v.is("suspend_threshold") )
        config.suspend_threshold = v.get_uint32();

    else if ( v.is("max_suspend_time") )
    {
        long t = clock_ticks(v.get_uint32());
        config.max_suspend_time = TO_DURATION(config.max_time, t);
    }
#ifdef REG_TEST
    else if ( v.is("test_timeout") )
        config.test_timeout = v.get_bool();
#endif
    else
        return false;

    return true;
}

LatencyModule::LatencyModule() : Module(s_name, s_help, s_params)
{ }

void LatencyModule::set_trace(const Trace* trace) const
{ latency_trace = trace; }

const TraceOption* LatencyModule::get_trace_options() const
{
#ifndef DEBUG_MSGS
    return nullptr;
#else
    static const TraceOption latency_trace_options(nullptr, 0, nullptr);
    return &latency_trace_options;
#endif
}

bool LatencyModule::set(const char* fqn, Value& v, SnortConfig* sc)
{
    const char* slp = "latency.packet";
    const char* slr = "latency.rule";

    if ( !strncmp(fqn, slp, strlen(slp)) )
        return latency_set(v, sc->latency->packet_latency);

    else if ( !strncmp(fqn, slr, strlen(slr)) )
        return latency_set(v, sc->latency->rule_latency);

    return true;
}

bool LatencyModule::end(const char*, int, SnortConfig* sc)
{
    PacketLatencyConfig& config = sc->latency->packet_latency;

    if (config.max_time > CLOCK_ZERO)
        config.force_enable = true;

    return true;
}

const RuleMap* LatencyModule::get_rules() const
{ return latency_rules; }

unsigned LatencyModule::get_gid() const
{ return GID_LATENCY; }

const PegInfo* LatencyModule::get_pegs() const
{ return latency_pegs; }

PegCount* LatencyModule::get_counts() const
{ return reinterpret_cast<PegCount*>(&latency_stats); }
