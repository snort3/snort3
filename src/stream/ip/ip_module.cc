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

// ip_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ip_module.h"

#include "ip_session.h"
#include "stream_ip.h"

using namespace snort;
using namespace std;

#define DEFRAG_IPOPTIONS_STR \
    "inconsistent IP options on fragmented packets"

#define DEFRAG_TEARDROP_STR \
    "teardrop attack"

#define DEFRAG_SHORT_FRAG_STR \
    "short fragment, possible DOS attempt"

#define DEFRAG_ANOMALY_OVERSIZE_STR \
    "fragment packet ends after defragmented packet"

#define DEFRAG_ANOMALY_ZERO_STR \
    "zero-byte fragment packet"

#define DEFRAG_ANOMALY_BADSIZE_SM_STR \
    "bad fragment size, packet size is negative"

#define DEFRAG_ANOMALY_BADSIZE_LG_STR \
    "bad fragment size, packet size is greater than 65536"

#define DEFRAG_ANOMALY_OVLP_STR \
    "fragmentation overlap"

#if 0  // OBE
#define DEFRAG_IPV6_BSD_ICMP_FRAG_STR
    "IPv6 BSD mbufs remote kernel buffer overflow"

#define DEFRAG_IPV6_BAD_FRAG_PKT_STR
    "bogus fragmentation packet, possible BSD attack"
#endif

#define DEFRAG_MIN_TTL_EVASION_STR \
    "TTL value less than configured minimum, not using for reassembly"

#define DEFRAG_EXCESSIVE_OVERLAP_STR \
    "excessive fragment overlap"

#define DEFRAG_TINY_FRAGMENT_STR \
    "tiny fragment"

FragEngine::FragEngine()
{
    memset(this, 0, sizeof(*this));
    frag_timeout = 60;
}

//-------------------------------------------------------------------------
// stream_ip module
//-------------------------------------------------------------------------

Trace TRACE_NAME(stream_ip);

static const RuleMap stream_ip_rules[] =
{
    { DEFRAG_IPOPTIONS, DEFRAG_IPOPTIONS_STR },
    { DEFRAG_TEARDROP, DEFRAG_TEARDROP_STR },
    { DEFRAG_SHORT_FRAG, DEFRAG_SHORT_FRAG_STR },
    { DEFRAG_ANOMALY_OVERSIZE, DEFRAG_ANOMALY_OVERSIZE_STR },
    { DEFRAG_ANOMALY_ZERO, DEFRAG_ANOMALY_ZERO_STR },
    { DEFRAG_ANOMALY_BADSIZE_SM, DEFRAG_ANOMALY_BADSIZE_SM_STR },
    { DEFRAG_ANOMALY_BADSIZE_LG, DEFRAG_ANOMALY_BADSIZE_LG_STR },
    { DEFRAG_ANOMALY_OVLP, DEFRAG_ANOMALY_OVLP_STR },
    { DEFRAG_MIN_TTL_EVASION, DEFRAG_MIN_TTL_EVASION_STR },
    { DEFRAG_EXCESSIVE_OVERLAP, DEFRAG_EXCESSIVE_OVERLAP_STR },
    { DEFRAG_TINY_FRAGMENT, DEFRAG_TINY_FRAGMENT_STR },

    { 0, nullptr }
};

static const Parameter s_params[] =
{
    { "max_frags", Parameter::PT_INT, "1:", "8192",
      "maximum number of simultaneous fragments being tracked" },

    { "max_overlaps", Parameter::PT_INT, "0:", "0",
      "maximum allowed overlaps per datagram; 0 is unlimited" },

    { "min_frag_length", Parameter::PT_INT, "0:", "0",
      "alert if fragment length is below this limit before or after trimming" },

    { "min_ttl", Parameter::PT_INT, "1:255", "1",
      "discard fragments with TTL below the minimum" },

    { "policy", Parameter::PT_ENUM, IP_POLICIES, "linux",
      "fragment reassembly policy" },

    { "session_timeout", Parameter::PT_INT, "1:86400", "30",
      "session tracking timeout" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

StreamIpModule::StreamIpModule() :
    Module(MOD_NAME, MOD_HELP, s_params, false, &TRACE_NAME(stream_ip))
{ config = nullptr; }

StreamIpModule::~StreamIpModule()
{
    if ( config )
        delete config;
}

const RuleMap* StreamIpModule::get_rules() const
{ return stream_ip_rules; }

ProfileStats* StreamIpModule::get_profile(
    unsigned index, const char*& name, const char*& parent) const
{
    switch ( index )
    {
    case 0:
        name = "stream_ip";
        parent = nullptr;
        return &ip_perf_stats;

    case 1:
        name = "frag";
        parent = "stream_ip";
        return &fragPerfStats;

    case 2:
        name = "frag_insert";
        parent = "frag";
        return &fragInsertPerfStats;

    case 3:
        name = "frag_rebuild";
        parent = "frag";
        return &fragRebuildPerfStats;
    }
    return nullptr;
}

StreamIpConfig* StreamIpModule::get_data()
{
    StreamIpConfig* temp = config;
    config = nullptr;
    return temp;
}

bool StreamIpModule::set(const char* f, Value& v, SnortConfig* c)
{
    if ( v.is("max_frags") )
        config->frag_engine.max_frags = v.get_long();

    else if ( v.is("max_overlaps") )
        config->frag_engine.max_overlaps = v.get_long();

    else if ( v.is("min_frag_length") )
        config->frag_engine.min_fragment_length = v.get_long();

    else if ( v.is("min_ttl") )
        config->frag_engine.min_ttl = v.get_long();

    else if ( v.is("policy") )
        config->frag_engine.frag_policy = v.get_long() + 1;

    else if ( v.is("session_timeout") )
    {
        // FIXIT-L need to integrate to eliminate redundant data
        config->session_timeout = v.get_long();
        config->frag_engine.frag_timeout = v.get_long();
    }
    else
        return Module::set(f, v, c);

    return true;
}

bool StreamIpModule::begin(const char*, int, SnortConfig*)
{
    if ( !config )
        config = new StreamIpConfig;

    return true;
}

bool StreamIpModule::end(const char*, int, SnortConfig*)
{
    return true;
}

const PegInfo* StreamIpModule::get_pegs() const
{ return ip_pegs; }

PegCount* StreamIpModule::get_counts() const
{ return (PegCount*)&ip_stats; }

