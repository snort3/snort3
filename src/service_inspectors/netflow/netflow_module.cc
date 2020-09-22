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

// netflow_module.cc author Shashikant Lad <shaslad@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "netflow_module.h"

#include "utils/util.h"

using namespace snort;

// -----------------------------------------------------------------------------
// static variables
// -----------------------------------------------------------------------------

static const Parameter netflow_params[] =
{
    { "dump_file", Parameter::PT_STRING, nullptr, nullptr,
      "file name to dump netflow cache on shutdown; won't dump by default" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo netflow_pegs[] =
{
    { CountType::SUM, "packets", "total packets processed" },
    { CountType::SUM, "records", "total records found in netflow data" },
    { CountType::SUM, "version_5", "count of netflow version 5 packets received" },
    { CountType::SUM, "version_9", "count of netflow version 9 packets received" },
    { CountType::SUM, "invalid_netflow_pkts", "count of invalid netflow packets" },
    { CountType::SUM, "unique_flows", "count of unique netflow flows" },
    { CountType::END, nullptr, nullptr},
};

//-------------------------------------------------------------------------
// netflow module
//-------------------------------------------------------------------------

NetflowModule::NetflowModule() : Module(NETFLOW_NAME, NETFLOW_HELP, netflow_params)
{
    conf = nullptr;
}

NetflowModule::~NetflowModule()
{
    delete conf;
}

NetflowConfig* NetflowModule::get_data()
{
    NetflowConfig* tmp = conf;
    conf = nullptr;
    return tmp;
}

bool NetflowModule::begin(const char*, int, SnortConfig*)
{
    assert(!conf);
    conf = new NetflowConfig();
    return true;
}

bool NetflowModule::set(const char*, Value& v, SnortConfig*)
{

    if ( v.is("dump_file") )
    {
        if ( conf->dump_file )
            snort_free((void*)conf->dump_file);
        conf->dump_file = snort_strdup(v.get_string());
    }
    else
        return false;

    return true;
}

PegCount* NetflowModule::get_counts() const
{ return (PegCount*)&netflow_stats; }

const PegInfo* NetflowModule::get_pegs() const
{ return netflow_pegs; }

ProfileStats* NetflowModule::get_profile() const
{ return &netflow_perf_stats; }

