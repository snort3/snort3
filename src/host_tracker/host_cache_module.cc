//--------------------------------------------------------------------------
// Copyright (C) 2016-2020 Cisco and/or its affiliates. All rights reserved.
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

// host_cache_module.cc author Steve Chew <stechew@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_cache_module.h"

#include <fstream>
#include <lua.hpp>
#include <sys/stat.h>

#include "log/messages.h"
#include "managers/module_manager.h"
#include "utils/util.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// commands
//-------------------------------------------------------------------------

static int host_cache_dump(lua_State* L)
{
    HostCacheModule* mod = (HostCacheModule*) ModuleManager::get_module(HOST_CACHE_NAME);
    if ( mod )
        mod->log_host_cache( luaL_optstring(L, 1, nullptr), true );
    return 0;
}

static const Parameter host_cache_cmd_params[] =
{
    { "file_name", Parameter::PT_STRING, nullptr, nullptr, "file name to dump host cache" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Command host_cache_cmds[] =
{
    { "dump", host_cache_dump, host_cache_cmd_params, "dump host cache"},
    { nullptr, nullptr, nullptr, nullptr }
};

const Command* HostCacheModule::get_commands() const
{
    return host_cache_cmds;
}

//-------------------------------------------------------------------------
// options
//-------------------------------------------------------------------------

static const Parameter host_cache_params[] =
{
    { "dump_file", Parameter::PT_STRING, nullptr, nullptr,
      "file name to dump host cache on shutdown; won't dump by default" },

    { "memcap", Parameter::PT_INT, "512:maxSZ", "8388608",
      "maximum host cache size in bytes" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

bool HostCacheModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("dump_file") )
    {
        if ( dump_file )
            snort_free((void*)dump_file);
        dump_file = snort_strdup(v.get_string());
    }
    else if ( v.is("memcap") )
        hc_rrt.memcap = v.get_size();
    else
        return false;

    return true;
}

bool HostCacheModule::begin(const char*, int, SnortConfig*)
{
    hc_rrt.memcap = 0;
    return true;
}

bool HostCacheModule::end(const char* fqn, int, SnortConfig* sc)
{
    if ( hc_rrt.memcap && !strcmp(fqn, HOST_CACHE_NAME) )
    {
        if ( Snort::is_reloading() )
            sc->register_reload_resource_tuner(hc_rrt);
        else
            host_cache.set_max_size(hc_rrt.memcap);
    }

    return true;
}

//-------------------------------------------------------------------------
// methods
//-------------------------------------------------------------------------

HostCacheModule::HostCacheModule() :
    Module(HOST_CACHE_NAME, HOST_CACHE_HELP, host_cache_params) { }

HostCacheModule::~HostCacheModule()
{
    if ( dump_file )
    {
        log_host_cache(dump_file);
        snort_free((void*)dump_file);
    }
}

void HostCacheModule::log_host_cache(const char* file_name, bool verbose)
{
    if ( !file_name )
    {
        if ( verbose )
            LogMessage("File name is needed!\n");
        return;
    }

    // Prevent damaging any existing file, intentionally or not
    struct stat file_stat;
    if ( stat(file_name, &file_stat) == 0 )
    {
        if ( verbose )
            LogMessage("File %s already exists!\n", file_name);
        return;
    }

    ofstream out_stream(file_name);
    if ( !out_stream )
    {
        if ( verbose )
            LogMessage("Couldn't open %s to write!\n", file_name);
        return;
    }

    string str;
    SfIpString ip_str;
    const auto&& lru_data = host_cache.get_all_data();
    // The current size may not exactly correspond to the number of trackers seen here
    // as packet threads may continue to update cache, except when dumping upon exit or pause
    out_stream << "Current host cache size: " << host_cache.mem_size() << " bytes, "
        << lru_data.size() << " trackers" << endl << endl;
    for ( const auto& elem : lru_data )
    {
        str = "IP: ";
        str += elem.first.ntop(ip_str);
        elem.second->stringify(str);
        out_stream << str << endl << endl;
    }
    out_stream.close();

    if ( verbose )
        LogMessage("Dumped host cache to %s\n", file_name);
}

const PegInfo* HostCacheModule::get_pegs() const
{ return host_cache.get_pegs(); }

PegCount* HostCacheModule::get_counts() const
{ return (PegCount*)host_cache.get_counts(); }

void HostCacheModule::sum_stats(bool accumulate_now_stats)
{
    host_cache.lock();
    Module::sum_stats(accumulate_now_stats);
    host_cache.unlock();
}
