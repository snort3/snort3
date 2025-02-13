//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

// ha_module.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef HA_MODULE_H
#define HA_MODULE_H

#include <sys/time.h>

#include "framework/module.h"

#define HA_NAME "high_availability"
#define HA_HELP "implement flow tracking high availability"

struct HighAvailabilityConfig
{
    ~HighAvailabilityConfig() { delete ports; }

    bool enabled;
    bool daq_channel;
    PortBitSet* ports = nullptr;
    struct timeval min_session_lifetime;
    struct timeval min_sync_interval;
};

class HighAvailabilityModule : public snort::Module
{
public:
    HighAvailabilityModule();
    ~HighAvailabilityModule() override;

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    snort::ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return GLOBAL; }

private:
    HighAvailabilityConfig* config;
};

struct HAStats
{
    PegCount msgs_recv;
    PegCount update_msgs_recv;
    PegCount update_msgs_recv_no_flow;
    PegCount update_msgs_consumed;
    PegCount delete_msgs_consumed;
    PegCount daq_stores;
    PegCount daq_imports;
    PegCount key_mismatch;
    PegCount msg_version_mismatch;
    PegCount msg_length_mismatch;
    PegCount truncated_msgs;
    PegCount unknown_key_type;
    PegCount unknown_client_idx;
    PegCount client_consume_errors;
};

extern THREAD_LOCAL HAStats ha_stats;
extern THREAD_LOCAL snort::ProfileStats ha_perf_stats;

#endif

