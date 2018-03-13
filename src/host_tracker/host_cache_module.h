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

// host_cache_module.h author Steve Chew <stechew@cisco.com>

#ifndef HOST_CACHE_MODULE_H
#define HOST_CACHE_MODULE_H

//  Loads host cache configuration data.

#include "framework/module.h"

#define host_cache_help \
    "configure hosts"

class HostCacheModule : public snort::Module
{
public:
    HostCacheModule() : snort::Module("host_cache", host_cache_help, host_cache_params, true)
    {
    }

    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    void sum_stats(bool) override;

    Usage get_usage() const override
    { return GLOBAL; }

private:
    static const snort::Parameter host_cache_params[];
    static const snort::Parameter service_params[];

    uint32_t host_cache_size;
};

#endif

