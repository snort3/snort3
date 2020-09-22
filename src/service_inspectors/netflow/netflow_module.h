//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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

// netflow_module.h author Shashikant Lad <shaslad@cisco.com>


#ifndef NETFLOW_MODULE_H
#define NETFLOW_MODULE_H

#include "framework/module.h"
#include "utils/util.h"

#define NETFLOW_NAME "netflow"
#define NETFLOW_HELP "netflow inspection"

namespace snort
{
struct SnortConfig;
}

struct NetflowConfig
{
    NetflowConfig() { dump_file = nullptr; }
    const char* dump_file;
};

struct NetflowStats
{
    PegCount packets;
    PegCount records;
    PegCount version_5;
    PegCount version_9;
    PegCount invalid_netflow_pkts;
    PegCount unique_flows;
};

extern THREAD_LOCAL NetflowStats netflow_stats;
extern THREAD_LOCAL snort::ProfileStats netflow_perf_stats;

class NetflowModule : public snort::Module
{
public:
    NetflowModule();
    ~NetflowModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;
    NetflowConfig* get_data();

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }

private:
     NetflowConfig* conf;

};

#endif
