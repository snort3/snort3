//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "latency_module.h"

#include <chrono>

#include "main/snort_config.h"
#include "latency_config.h"
#include "latency_stats.h"
#include "latency_rules.h"

// -----------------------------------------------------------------------------
// latency attributes
// -----------------------------------------------------------------------------

#define s_name "latency"
#define s_help \
    "packet and rule latency monitoring and control"

static const Parameter s_packet_params[] =
{
    { "enable", Parameter::PT_BOOL, nullptr, "true",
        "enable packet latency" },

    { "max_time", Parameter::PT_INT, "0:", "0",
        "set timeout for packet latency thresholding (usec)" },

    { "fastpath", Parameter::PT_BOOL, nullptr, "false",
        "fastpath expensive packets (max_time exceeded)" },

    { "action", Parameter::PT_ENUM, "none | alert | log | alert_and_log", "alert_and_log",
        "event action if packet latency times out" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "packet", Parameter::PT_TABLE, s_packet_params, nullptr,
      "packet latency" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap latency_rules[] =
{
    { LATENCY_EVENT_PACKET_FASTPATHED, "packet fastpathed due to latency" },

    { 0, nullptr }
};

THREAD_LOCAL LatencyStats latency_stats;

static const PegInfo latency_pegs[] =
{
    { "packets", "total packets monitored" },
    { "timeouts", "packets that timed out" },
    { nullptr, nullptr }
};

// -----------------------------------------------------------------------------
// latency module
// -----------------------------------------------------------------------------

static inline bool latency_set(Value& v, PacketLatencyConfig& config)
{
    using std::chrono::duration_cast;
    using std::chrono::microseconds;

    if ( v.is("enable") )
        config.enable = v.get_bool();

    else if ( v.is("max_time") )
        config.max_time =
            duration_cast<decltype(config.max_time)>(microseconds(v.get_long()));

    else if ( v.is("fastpath") )
        config.fastpath = v.get_bool();

    else if ( v.is("action") )
        config.action =
            static_cast<decltype(config.action)>(v.get_long());

    else
        return false;

    return true;
}

LatencyModule::LatencyModule() :
    Module(s_name, s_help, s_params)
{ }

bool LatencyModule::set(const char* fqn, Value& v, SnortConfig* sc)
{
    const char* slp = "latency.packet";

    if ( !strncmp(fqn, slp, strlen(slp)) )
        return latency_set(v, sc->latency->packet_latency);
    else
        return false;

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
