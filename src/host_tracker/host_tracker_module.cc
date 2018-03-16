//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_config.h"
#include "stream/stream.h"
#include "target_based/snort_protocols.h"

#include "host_cache.h"

using namespace snort;

const PegInfo host_tracker_pegs[] =
{
    { CountType::SUM, "service_adds", "host service adds" },
    { CountType::SUM, "service_finds", "host service finds" },
    { CountType::SUM, "service_removes", "host service removes" },
    { CountType::END, nullptr, nullptr },
};

const Parameter HostTrackerModule::service_params[] =
{
    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "service identifier" },

    { "proto", Parameter::PT_ENUM, "tcp | udp", "tcp",
      "IP protocol" },

    { "port", Parameter::PT_PORT, nullptr, nullptr,
      "port number" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

const Parameter HostTrackerModule::host_tracker_params[] =
{
    { "IP", Parameter::PT_ADDR, nullptr, "0.0.0.0/32",
      "hosts address / cidr" },

    { "frag_policy", Parameter::PT_ENUM, IP_POLICIES, nullptr,
      "defragmentation policy" },

    { "tcp_policy", Parameter::PT_ENUM, TCP_POLICIES, nullptr,
      "TCP reassembly policy" },

    { "services", Parameter::PT_LIST, HostTrackerModule::service_params, nullptr,
      "list of service parameters" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

bool HostTrackerModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( host and v.is("ip") )
    {
        SfIp addr;
        v.get_addr(addr);
        host->set_ip_addr(addr);
    }
    else if ( host and v.is("frag_policy") )
        host->set_frag_policy(v.get_long() + 1);

    else if ( host and v.is("tcp_policy") )
        host->set_stream_policy(v.get_long() + 1);

    else if ( v.is("name") )
        app.snort_protocol_id = sc->proto_ref->add(v.get_string());

    else if ( v.is("proto") )
        app.ipproto = sc->proto_ref->add(v.get_string());

    else if ( v.is("port") )
        app.port = v.get_long();

    else
        return false;

    return true;
}

bool HostTrackerModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, "host_tracker") )
        host = new HostTracker;

    return true;
}

bool HostTrackerModule::end(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, "host_tracker.services") )
    {
        host->add_service(app);
        memset(&app, 0, sizeof(app));
    }
    else if ( idx && !strcmp(fqn, "host_tracker") )
    {
        host_cache_add_host_tracker(host);
        host = nullptr;  //  Host cache is now responsible for freeing host
    }

    return true;
}

const PegInfo* HostTrackerModule::get_pegs() const
{ return host_tracker_pegs; }

PegCount* HostTrackerModule::get_counts() const
{ return (PegCount*)&host_tracker_stats; }

