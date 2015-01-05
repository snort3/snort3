/*
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

// stream_module.cc author Russ Combs <rucombs@cisco.com>

#include "stream_module.h"

#include <string>
using namespace std;

#include "main/snort_config.h"
#include "stream/stream.h"

static constexpr unsigned K = 1024;

static StreamModuleConfig stream_cfg = 
{
    // bytes, #, sec, sec
    { 8*K,  16*K, 30, 180 },  // ip
    { 8*K,  32*K, 30, 180 },  // icmp
    { 8*K, 128*K, 30, 180 },  // tcp
    { 8*K,  64*K, 30, 180 },  // udp
};

//-------------------------------------------------------------------------
// stream module
//-------------------------------------------------------------------------

static const Parameter proto_params[] =
{
    { "memcap", Parameter::PT_INT, "0:", nullptr,
      "maximum cache memory" },

    { "idle_timeout", Parameter::PT_INT, "1:", "60",
      "maximum inactive time before retiring session tracker" },

    { "pruning_timeout", Parameter::PT_INT, "1:", "30",
      "minimum inactive time before being eligible for pruning" },

    { "max_sessions", Parameter::PT_INT, "0:", "262144",
      "maximum simultaneous tcp sessions tracked before pruning" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "icmp_cache", Parameter::PT_TABLE, proto_params, nullptr,
      "configure icmp cache limits" },

    { "ip_cache", Parameter::PT_TABLE, proto_params, nullptr,
      "configure ip cache limits" },

    { "tcp_cache", Parameter::PT_TABLE, proto_params, nullptr,
      "configure tcp cache limits" },

    { "udp_cache", Parameter::PT_TABLE, proto_params, nullptr,
      "configure udp cache limits" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

StreamModule::StreamModule() :
    Module(MOD_NAME, MOD_HELP, s_params)
{
    proto = &stream_cfg.ip_cfg;
}

const PegInfo* StreamModule::get_pegs() const
{ return base_pegs; }

ProfileStats* StreamModule::get_profile() const
{ return &s5PerfStats; }

const StreamModuleConfig* StreamModule::get_data()
{
    return &stream_cfg;
}

bool StreamModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("memcap") )
        proto->mem_cap = v.get_long();

    else if ( v.is("max_sessions") )
        proto->max_sessions = v.get_long();

    else if ( v.is("pruning_timeout") )
        proto->cache_pruning_timeout = v.get_long();

    else if ( v.is("idle_timeout") )
        proto->cache_nominal_timeout = v.get_long();

    else
        return false;

    return true;
}

bool StreamModule::begin(const char* fqn, int, SnortConfig*)
{
    if ( !strcmp(fqn, "stream.tcp_cache") )
        proto = &stream_cfg.tcp_cfg;

    else if ( !strcmp(fqn, "stream.udp_cache") )
        proto = &stream_cfg.udp_cfg;

    else if ( !strcmp(fqn, "stream.icmp_cache") )
        proto = &stream_cfg.icmp_cfg;

    else if ( !strcmp(fqn, "stream.ip_cache") )
        proto = &stream_cfg.ip_cfg;

    else if ( strcmp(fqn, "stream") )
        return false;

    return true;
}

void StreamModule::sum_stats()
{ base_sum(); }

void StreamModule::show_stats()
{ base_stats(); }

void StreamModule::reset_stats()
{ base_reset(); }

