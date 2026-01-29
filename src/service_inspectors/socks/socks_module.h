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

// socks_module.h author Raza Shafiq <rshafiq@cisco.com>

#ifndef SOCKS_MODULE_H
#define SOCKS_MODULE_H

#include "framework/module.h"
#include "framework/decode_data.h"
#include "profiler/profiler.h"
#include "trace/trace_api.h"

#define SOCKS_NAME "socks"
#define SOCKS_HELP "SOCKS protocol inspector"

#define GID_SOCKS 155

enum SocksEvent : uint32_t
{
    // SOCKS protocol anomaly events (security-relevant only)
    SOCKS_EVENT_UNKNOWN_COMMAND = 1,
    SOCKS_EVENT_PROTOCOL_VIOLATION,
    
    // SOCKS5-specific events
    SOCKS5_EVENT_UNKNOWN_ADDRESS_TYPE,
    SOCKS5_EVENT_UDP_FRAGMENTATION
};

enum SocksPeg : uint32_t
{
    SOCKS_PEG_SESSIONS = 0,
    SOCKS_PEG_CONCURRENT_SESSIONS,
    SOCKS_PEG_MAX_CONCURRENT_SESSIONS,
    SOCKS_PEG_AUTH_REQUESTS,
    SOCKS_PEG_AUTH_SUCCESSES,
    SOCKS_PEG_AUTH_FAILURES,
    SOCKS_PEG_CONNECT_REQUESTS,
    SOCKS_PEG_BIND_REQUESTS,
    SOCKS_PEG_UDP_ASSOCIATE_REQUESTS,
    SOCKS_PEG_SUCCESSFUL_CONNECTIONS,
    SOCKS_PEG_FAILED_CONNECTIONS,
    SOCKS_PEG_UDP_ASSOCIATIONS_CREATED,
    SOCKS_PEG_UDP_EXPECTATIONS_CREATED,
    SOCKS_PEG_UDP_PACKETS,
    SOCKS_PEG_UDP_FRAGS_DROPPED,
    SOCKS_PEG_UDP_FRAGS_BLOCKED,
    SOCKS_PEG_MAX
};

extern const PegInfo socks_pegs[];

struct SocksStats
{
    PegCount sessions;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
    PegCount auth_requests;
    PegCount auth_successes;
    PegCount auth_failures;
    PegCount connect_requests;
    PegCount bind_requests;
    PegCount udp_associate_requests;
    PegCount successful_connections;
    PegCount failed_connections;
    PegCount udp_associations_created;
    PegCount udp_expectations_created;
    PegCount udp_packets;
    PegCount udp_frags_dropped;
    PegCount udp_frags_blocked;
};

extern THREAD_LOCAL SocksStats socks_stats;
extern THREAD_LOCAL snort::ProfileStats socksPerfStats;

struct SocksConfig
{
    bool block_udp_fragmentation = true;     // Block flow on UDP fragmentation (default: true)
};

class SocksModule : public snort::Module
{
public:
    SocksModule();
    ~SocksModule() override;

    unsigned get_gid() const override
    { return GID_SOCKS; }

    const snort::RuleMap* get_rules() const override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    snort::ProfileStats* get_profile() const override
    { return &socksPerfStats; }

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }
    
    const SocksConfig* get_config() const
    { return config; }

private:
    SocksConfig* config;
};

#endif
