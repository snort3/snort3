//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// socks_module.cc author Raza Shafiq <rshafiq@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "socks_module.h"

#include "framework/decode_data.h"
#include "socks.h"

using namespace snort;

// Performance counters
const PegInfo socks_pegs[] =
{
    { CountType::SUM, "sessions", "total SOCKS sessions" },
    { CountType::NOW, "concurrent_sessions", "current concurrent SOCKS sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent SOCKS sessions" },
    { CountType::SUM, "auth_requests", "authentication requests" },
    { CountType::SUM, "auth_successes", "successful authentications" },
    { CountType::SUM, "auth_failures", "failed authentications" },
    { CountType::SUM, "connect_requests", "CONNECT requests" },
    { CountType::SUM, "bind_requests", "BIND requests" },
    { CountType::SUM, "udp_associate_requests", "UDP ASSOCIATE requests" },
    { CountType::SUM, "successful_connections", "successful connections" },
    { CountType::SUM, "failed_connections", "failed connections" },
    { CountType::SUM, "udp_associations_created", "UDP ASSOCIATE completions" },
    { CountType::SUM, "udp_expectations_created", "UDP expectations created for dynamic ports" },
    { CountType::SUM, "udp_packets", "UDP packets processed" },
    { CountType::SUM, "udp_frags_dropped", "UDP fragments dropped" },
    { CountType::SUM, "udp_frags_blocked", "flows blocked due to UDP fragmentation" },
    { CountType::END, nullptr, nullptr }
};

static const Parameter socks_params[] =
{
    { "block_udp_fragmentation", Parameter::PT_BOOL, nullptr, "true",
      "block flow when SOCKS5 UDP fragmentation detected (frag > 0)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap socks_rules[] =
{
    // SOCKS protocol anomaly events (security-relevant only)
    { SOCKS_EVENT_UNKNOWN_COMMAND, "SOCKS unknown command" },
    { SOCKS_EVENT_PROTOCOL_VIOLATION, "SOCKS protocol violation" },
    
    // SOCKS5-specific events
    { SOCKS5_EVENT_UNKNOWN_ADDRESS_TYPE, "SOCKS5 unknown address type" },
    { SOCKS5_EVENT_UDP_FRAGMENTATION, "SOCKS5 UDP fragmentation detected" },
    
    { 0, nullptr }
};

SocksModule::SocksModule() : Module(SOCKS_NAME, SOCKS_HELP, socks_params)
{
    config = nullptr;
}

SocksModule::~SocksModule()
{
    if ( config )
        delete config;
}

bool SocksModule::set(const char*, Value& v, SnortConfig*)
{
    assert(config);

    if ( v.is("block_udp_fragmentation") )
        config->block_udp_fragmentation = v.get_bool();
    else
        return false;

    return true;
}

bool SocksModule::begin(const char*, int, SnortConfig*)
{
    if ( !config )
        config = new SocksConfig();
    return true;
}

bool SocksModule::end(const char*, int, SnortConfig*)
{
    return true;
}

const RuleMap* SocksModule::get_rules() const
{ return socks_rules; }

const PegInfo* SocksModule::get_pegs() const
{ return socks_pegs; }

PegCount* SocksModule::get_counts() const
{ return const_cast<PegCount*>(reinterpret_cast<const PegCount*>(&socks_stats)); }
