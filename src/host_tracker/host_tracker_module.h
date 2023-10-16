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

// host_tracker_module.h author Steve Chew <stechew@cisco.com>

#ifndef HOST_TRACKER_MODULE_H
#define HOST_TRACKER_MODULE_H

//  Loads host configuration data.

// FIXIT-M temporarily create new HostTracker module to test new
// HostTracker object.  May eventually replace old Hosts module with this
// one.

#include <cassert>
#include <vector>

#include "framework/module.h"
#include "host_tracker/cache_allocator.cc"
#include "host_tracker/host_cache.h"

#define host_tracker_help \
    "configure hosts"
#define HOST_TRACKER_NAME "host_tracker"

class HostTrackerModule : public snort::Module
{
public:
    HostTrackerModule() :
        snort::Module(HOST_TRACKER_NAME, host_tracker_help, host_tracker_params, true) { }

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    void init_data();

    Usage get_usage() const override
    { return GLOBAL; }

private:
    static const snort::Parameter host_tracker_params[];
    static const snort::Parameter service_params[];

    std::vector<snort::HostApplication> apps;
    snort::HostApplication app;
    snort::SfIp addr;
};

#endif

