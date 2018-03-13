//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "host_cache.h"

using namespace snort;

const Parameter HostCacheModule::host_cache_params[] =
{
    { "size", Parameter::PT_INT, nullptr, nullptr,
      "size of host cache" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

bool HostCacheModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("size") )
        host_cache_size = v.get_long();
    else
        return false;

    return true;
}

bool HostCacheModule::begin(const char*, int, SnortConfig*)
{
    host_cache_size = 0;
    return true;
}

bool HostCacheModule::end(const char* fqn, int, SnortConfig*)
{
    if ( host_cache_size && !strcmp(fqn, "host_cache") )
    {
        host_cache.set_max_size(host_cache_size);
    }

    return true;
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
