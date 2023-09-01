//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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

// host_tracker_module.cc author Steve Chew <stechew@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_tracker_module.h"
#include "host_cache_segmented.h"

#include "log/messages.h"
#include "main/snort_config.h"

#include "cache_allocator.cc"

using namespace snort;

static HostCacheIp initial_host_cache(LRU_CACHE_INITIAL_SIZE);

const PegInfo host_tracker_pegs[] =
{
    { CountType::SUM, "service_adds", "host service adds" },
    { CountType::SUM, "service_finds", "host service finds" },
    { CountType::END, nullptr, nullptr },
};

const Parameter HostTrackerModule::service_params[] =
{
    { "port", Parameter::PT_PORT, nullptr, nullptr, "port number" },

    { "proto", Parameter::PT_ENUM, "ip | tcp | udp", nullptr, "IP protocol" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

const Parameter HostTrackerModule::host_tracker_params[] =
{
    { "ip", Parameter::PT_ADDR, nullptr, nullptr, "hosts address / cidr" },

    { "services", Parameter::PT_LIST, HostTrackerModule::service_params, nullptr,
      "list of service parameters" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

bool HostTrackerModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("ip") )
        v.get_addr(addr);

    else if ( v.is("port") )
        app.port = v.get_uint16();

    else if ( v.is("proto") )
    {
        const IpProtocol mask[] =
        { IpProtocol::IP, IpProtocol::TCP, IpProtocol::UDP };
        app.proto = mask[v.get_uint8()];
    }

    return true;
}

bool HostTrackerModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, "host_tracker") )
    {
        addr.clear();
        apps.clear();
    }
    return true;
}

bool HostTrackerModule::end(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, "host_tracker.services") )
        apps.emplace_back(app);

    else if ( idx && !strcmp(fqn, "host_tracker") && addr.is_set() )
    {
        initial_host_cache[addr];

        for ( auto& a : apps )
            initial_host_cache[addr]->add_service(a);

        addr.clear();
        apps.clear();
    }

    return true;
}

void HostTrackerModule::init_data()
{
    auto host_data = initial_host_cache.get_all_data();
    for ( auto& h : host_data )
    {
        host_cache.find_else_insert(h.first, h.second);
        h.second->init_visibility(1);
    }
}


const PegInfo* HostTrackerModule::get_pegs() const
{ return host_tracker_pegs; }

PegCount* HostTrackerModule::get_counts() const
{ return (PegCount*)&host_tracker_stats; }
