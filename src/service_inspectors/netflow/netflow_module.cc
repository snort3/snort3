//--------------------------------------------------------------------------
// Copyright (C) 2020-2021 Cisco and/or its affiliates. All rights reserved.
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
static const Parameter device_rule_params[] =
{
    { "device_ip", Parameter::PT_ADDR, nullptr, nullptr,
      "restrict the NetFlow devices from which Snort will analyze packets" },

    { "exclude", Parameter::PT_BOOL, nullptr, "false",
      "exclude the NetFlow records that match this rule" },

    { "zones", Parameter::PT_STRING, nullptr, nullptr,
      "generate events only for NetFlow packets that originate from these zones" },

    { "networks", Parameter::PT_STRING, nullptr, nullptr,
      "generate events for NetFlow records that contain an initiator or responder IP from these networks" },

    { "create_host", Parameter::PT_BOOL, nullptr, "false",
      "generate a new host event" },

    { "create_service", Parameter::PT_BOOL, nullptr, "false",
      "generate a new or changed service event" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter netflow_params[] =
{
    { "dump_file", Parameter::PT_STRING, nullptr, nullptr,
      "file name to dump netflow cache on shutdown; won't dump by default" },

    { "update_timeout", Parameter::PT_INT, "0:max32", "3600",
      "the interval at which the system updates host cache information" },

    { "rules", Parameter::PT_LIST, device_rule_params, nullptr,
      "list of NetFlow device rules" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo netflow_pegs[] =
{
    { CountType::SUM, "invalid_netflow_record", "count of invalid netflow records" },
    { CountType::SUM, "packets", "total packets processed" },
    { CountType::SUM, "records", "total records found in netflow data" },
    { CountType::SUM, "unique_flows", "count of unique netflow flows" },
    { CountType::SUM, "v9_missing_template", "count of data records that are missing templates" },
    { CountType::SUM, "v9_options_template", "count of options template flowset" },
    { CountType::SUM, "v9_templates", "count of total version 9 templates" },
    { CountType::SUM, "version_5", "count of netflow version 5 packets received" },
    { CountType::SUM, "version_9", "count of netflow version 9 packets received" },
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

bool NetflowModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( !conf )
    {
        conf = new NetflowConfig();
    }

    if ( idx && !strcmp(fqn, "netflow.rules") )
    {
        rule_cfg.reset();
        device_ip_cfg.clear();
        is_exclude_rule = false;
    }
    return true;
}

bool NetflowModule::end(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, "netflow.rules") )
    {
        if ( device_ip_cfg.is_set() )
        {
            auto& d = conf->device_rule_map[device_ip_cfg];
            if ( is_exclude_rule )
                d.exclude.emplace_back(rule_cfg);
            else
                d.include.emplace_back(rule_cfg);
        }
    }

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
    else if ( v.is("update_timeout") )
    {
        conf->update_timeout = v.get_uint32();
    }
    else if ( v.is("device_ip") )
    {
        v.get_addr(device_ip_cfg);
    }
    else if ( v.is("networks") )
    {
        std::string net;
        v.set_first_token();
        for ( int i = 0; v.get_next_token(net); i++ )
        {
            SfCidr n;
            if ( n.set(net.c_str()) != SFIP_SUCCESS )
                return false;
            rule_cfg.networks.emplace_back(n);
        }
    }
    else if ( v.is("zones") )
    {
        std::string zone;
        v.set_first_token();
        for ( int i = 0; v.get_next_token(zone); i++ )
        {
            if ( zone == "any" )
            {
                rule_cfg.zones.clear();
                rule_cfg.zones.emplace_back(NETFLOW_ANY_ZONE);
                break;
            }
            int z = std::stoi(zone);
            if ( z < 0 or z >= NETFLOW_MAX_ZONES )
                return false;
            rule_cfg.zones.emplace_back(z);
        }
    }
    else if ( v.is("exclude") )
    {
        is_exclude_rule = v.get_bool();
    }
    else if ( v.is("create_host") )
    {
        rule_cfg.create_host = v.get_bool();
    }
    else if ( v.is("create_service") )
    {
        rule_cfg.create_service = v.get_bool();
    }
    return true;
}

PegCount* NetflowModule::get_counts() const
{ return (PegCount*)&netflow_stats; }

const PegInfo* NetflowModule::get_pegs() const
{ return netflow_pegs; }

ProfileStats* NetflowModule::get_profile() const
{ return &netflow_perf_stats; }
