//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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
#include "host_cache_allocator.cc"

#include "log/messages.h"
#include "main/snort_config.h"

using namespace snort;

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
        host_cache[addr]->update_service_port(app, v.get_uint16());

    else if ( v.is("proto") )
    {
        const IpProtocol mask[] =
        { IpProtocol::IP, IpProtocol::TCP, IpProtocol::UDP };
        host_cache[addr]->update_service_proto(app, mask[v.get_uint8()]);
    }

    return true;
}

bool HostTrackerModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, "host_tracker") )
    {
        addr.clear();
    }
    return true;
}

bool HostTrackerModule::end(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, "host_tracker.services") )
    {
        if ( addr.is_set() )
            host_cache[addr]->add_service(app);

        host_cache[addr]->clear_service(app);
    }
    else if ( idx && !strcmp(fqn, "host_tracker") && addr.is_set() )
    {
        host_cache[addr];
        host_cache[addr]->clear_service(app);
        addr.clear();
    }

    return true;
}

const PegInfo* HostTrackerModule::get_pegs() const
{ return host_tracker_pegs; }

PegCount* HostTrackerModule::get_counts() const
{ return (PegCount*)&host_tracker_stats; }
