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

// host_cache_module.h author Steve Chew <stechew@cisco.com>

#ifndef HOST_CACHE_MODULE_H
#define HOST_CACHE_MODULE_H

//  Loads host cache configuration data.

#include "framework/module.h"
#include "main/snort.h"
#include "main/reload_tuner.h"

#include "host_cache.h"

#define HOST_CACHE_NAME "host_cache"
#define HOST_CACHE_HELP "global LRU cache of host_tracker data about hosts"

class HostCacheReloadTuner : public snort::ReloadResourceTuner
{
public:
    explicit HostCacheReloadTuner(size_t memcap) : memcap(memcap) { }
    bool tinit() override
    { return host_cache.reload_resize(memcap); }

    bool tune_idle_context() override
    { return host_cache.reload_prune(memcap, max_work_idle); }

    bool tune_packet_context() override
    { return host_cache.reload_prune(memcap, max_work); }

private:
    size_t memcap;
};

class HostCacheModule : public snort::Module
{
public:
    HostCacheModule();
    ~HostCacheModule() override;

    bool end(const char*, int, snort::SnortConfig*) override;
    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    const snort::Command* get_commands() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    void sum_stats(bool) override;

    // in sum_stats, just populate the counts vector with whatever we have now
    bool global_stats() const override
    { return true; }

    Usage get_usage() const override
    { return GLOBAL; }

    void log_host_cache(const char* file_name, bool verbose = false);
    std::string get_host_cache_stats();

private:
    const char* dump_file = nullptr;
    size_t memcap = 0;
};

#endif

