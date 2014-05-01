/*
 ** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 ** Copyright (C) 2004-2013 Sourcefire, Inc.
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License Version 2 as
 ** published by the Free Software Foundation.  You may not use, modify or
 ** distribute this program under any other version of the GNU General
 ** Public License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

// defrag_module.cc author Russ Combs <rucombs@cisco.com>

#include "defrag_module.h"

#define DEFRAG_IPOPTIONS_STR \
    "(defrag) Inconsistent IP Options on Fragmented Packets"

#define DEFRAG_TEARDROP_STR \
    "(defrag) Teardrop attack"

#define DEFRAG_SHORT_FRAG_STR \
    "(defrag) Short fragment, possible DoS attempt"

#define DEFRAG_ANOMALY_OVERSIZE_STR \
    "(defrag) Fragment packet ends after defragmented packet"

#define DEFRAG_ANOMALY_ZERO_STR \
    "(defrag) Zero-byte fragment packet"

#define DEFRAG_ANOMALY_BADSIZE_SM_STR \
    "(defrag) Bad fragment size, packet size is negative"

#define DEFRAG_ANOMALY_BADSIZE_LG_STR \
    "(defrag) Bad fragment size, packet size is greater than 65536"

#define DEFRAG_ANOMALY_OVLP_STR \
    "(defrag) Fragmentation overlap"

#if 0  // OBE
#define DEFRAG_IPV6_BSD_ICMP_FRAG_STR
    "(defrag) IPv6 BSD mbufs remote kernel buffer overflow"

#define DEFRAG_IPV6_BAD_FRAG_PKT_STR
    "(defrag) Bogus fragmentation packet. Possible BSD attack"
#endif

#define DEFRAG_MIN_TTL_EVASION_STR \
    "(defrag) TTL value less than configured minimum, not using for reassembly"

#define DEFRAG_EXCESSIVE_OVERLAP_STR \
    "(defrag) Excessive fragment overlap"

#define DEFRAG_TINY_FRAGMENT_STR \
    "(defrag) Tiny fragment"

FragCommon::FragCommon()
{ 
    memset(this, 0, sizeof(*this));
    max_frags = 8192;
    memcap = 4194304;
}

FragEngine::FragEngine()
{ memset(this, 0, sizeof(*this)); }

//-------------------------------------------------------------------------
// defrag global module
//-------------------------------------------------------------------------

static const Parameter defrag_global_params[] =
{
    { "memcap", Parameter::PT_INT, "16384:", "4194304",
      "fragment memory pool size" },

    { "max_frags", Parameter::PT_INT, "1:", "8192",
      "maximum number of simultaneous fragments being tracked" },

    // FIXIT prealloc_memcap / prealloc_frags should be same as memcap /
    // max_frags + bool prealloc, no?
    { "prealloc_memcap", Parameter::PT_INT, "16384:", "0",
      "preallocated fragment memory pool size" },

    { "prealloc_frags", Parameter::PT_INT, "1:", "0",
      "number of fragment nodes to preallocate" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

DefragModule::DefragModule() :
    Module(GLOBAL_KEYWORD, defrag_global_params)
{
    common = nullptr;
}

DefragModule::~DefragModule()
{
    if ( common )
        delete common;
}

bool DefragModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("memcap") )
        common->memcap = v.get_long();

    else if ( v.is("max_frags") )
        common->max_frags = v.get_long();

    else if ( v.is("prealloc_memcap") )
    {
        common->use_prealloc = true;
        common->memcap = v.get_long();
    }
    else if ( v.is("prealloc_frags") )
        common->use_prealloc = common->use_prealloc_frags = true;

    else
        return false;

    return true;
}

bool DefragModule::begin(const char*, int, SnortConfig*)
{
    common = new FragCommon;
    return true;
}

FragCommon* DefragModule::get_data()
{
    FragCommon* tmp = common;
    common = nullptr;
    return tmp;
}

//-------------------------------------------------------------------------
// defrag engine module
//-------------------------------------------------------------------------

static const char* policies = 
    "first | linux | bsd | bsd_right |last | windows | solaris";

static const Parameter defrag_engine_params[] =
{
    { "detect_anomalies", Parameter::PT_BOOL, nullptr, "false",
      "detect fragment anomalies" },

    { "min_frag_length", Parameter::PT_INT, "0:", "0",
      "alert if fragment length is below this limit before or after trimming" },

    { "min_ttl", Parameter::PT_INT, "1:255", "1",
      "discard fragments with ttl below the minimum" },

    { "overlap_limit", Parameter::PT_INT, "0:", "0",
      "maximum allowed overlaps per datagram; 0 is unlimited; implies detect_anomalies" },

    { "policy", Parameter::PT_ENUM, policies, "linux",
      "fragment reassembly policy" },

    { "timeout", Parameter::PT_INT, "0:", "60",
      "discard fragments after timeout seconds" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap defrag_engine_rules[] =
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

DefragEngineModule::DefragEngineModule() :
    Module(ENGINE_KEYWORD, defrag_engine_params, defrag_engine_rules)
{
    engine = nullptr;
}

DefragEngineModule::~DefragEngineModule()
{
    if ( engine )
        delete engine;
}

bool DefragEngineModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("detect_anomalies") )
        engine->min_ttl = v.get_bool();

    else if ( v.is("min_frag_length") )
        engine->min_fragment_length = v.get_long();

    else if ( v.is("min_ttl") )
        engine->min_ttl = v.get_long();

    else if ( v.is("overlap_limit") )
        engine->overlap_limit = v.get_long();

    else if ( v.is("policy") )
        engine->frag_timeout = v.get_long() + 1;

    else if ( v.is("timeout") )
        engine->frag_timeout = v.get_long();

    else
        return false;

    return true;
}

bool DefragEngineModule::begin(const char*, int, SnortConfig*)
{
    engine = new FragEngine;
    return true;
}

FragEngine* DefragEngineModule::get_data()
{
    FragEngine* tmp = engine;
    engine = nullptr;
    return tmp;
}

