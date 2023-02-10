//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "netflow_cache.h"
#include "netflow_module.h"

#include "utils/util.h"

using namespace snort;

extern THREAD_LOCAL NetFlowCache* netflow_cache;
extern THREAD_LOCAL TemplateFieldCache* template_cache;
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

    { "flow_memcap", Parameter::PT_INT, "0:maxSZ", "0",
      "maximum memory for flow record cache in bytes, 0 = unlimited" },

    { "template_memcap", Parameter::PT_INT, "0:maxSZ", "0",
      "maximum memory for template cache in bytes, 0 = unlimited" },

    { "netflow_service_id_path", Parameter::PT_STRING, nullptr, nullptr,
      "path to file containing service IDs for NetFlow" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo netflow_pegs[] =
{
    LRU_CACHE_LOCAL_PEGS("netflow"),
    { CountType::SUM, "invalid_netflow_record", "count of invalid netflow records" },
    { CountType::SUM, "packets", "total packets processed" },
    { CountType::SUM, "records", "total records found in netflow data" },
    { CountType::SUM, "unique_flows", "count of unique netflow flows" },
    { CountType::SUM, "v9_missing_template", "count of data records that are missing templates" },
    { CountType::SUM, "v9_options_template", "count of options template flowset" },
    { CountType::SUM, "v9_templates", "count of total version 9 templates" },
    { CountType::SUM, "version_5", "count of netflow version 5 packets received" },
    { CountType::SUM, "version_9", "count of netflow version 9 packets received" },
    { CountType::NOW, "netflow_cache_bytes_in_use", "number of bytes used in netflow cache" },
    { CountType::NOW, "template_cache_bytes_in_use", "number of bytes used in template cache" },
    { CountType::END, nullptr, nullptr},
};

unsigned NetFlowModule::module_id = 0;

//-------------------------------------------------------------------------
// netflow module
//-------------------------------------------------------------------------

NetFlowModule::NetFlowModule() : Module(NETFLOW_NAME, NETFLOW_HELP, netflow_params)
{ }

NetFlowModule::~NetFlowModule()
{
    delete conf;
}

NetFlowConfig* NetFlowModule::get_data()
{
    NetFlowConfig* tmp = conf;
    conf = nullptr;
    return tmp;
}

bool NetFlowModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( !conf )
    {
        conf = new NetFlowConfig();
    }

    if ( idx && !strcmp(fqn, "netflow.rules") )
    {
        rule_cfg.reset();
        device_ip_cfg.clear();
        is_exclude_rule = false;
    }
    return true;
}

bool NetFlowModule::end(const char* fqn, int idx, SnortConfig*)
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
bool NetFlowModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("flow_memcap") )
        conf->flow_memcap = v.get_size();
    else if ( v.is("template_memcap") )
        conf->template_memcap = v.get_size();
    else if ( v.is("dump_file") )
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
    else if ( v.is("netflow_service_id_path") )
    {
        parse_service_id_file(v.get_string());
    }
    return true;
}

void NetFlowModule::parse_service_id_file(const std::string& serv_id_file_path)
{
    std::string serv_line;
    std::ifstream serv_id_file;
    serv_id_file.open(serv_id_file_path);

    if ( serv_id_file.is_open() )
    {
        while ( std::getline(serv_id_file, serv_line) )
        {
            std::stringstream ss(serv_line);
            std::vector<std::string> tokens;

            std::string tmp_str;

            while( std::getline(ss, tmp_str, '\t') )
                tokens.push_back(tmp_str);

            // Format is <port> <tcp/udp> <internal ID>
            uint16_t srv_port = std::stoi(tokens[0]);
            std::string proto_str = tokens[1];
            uint16_t id = std::stoi(tokens[2]);

            if ( proto_str == "tcp" )
                tcp_service_mappings[srv_port] = id;
            else if ( proto_str == "udp" )
                udp_service_mappings[srv_port] = id;
        }
    }
}

PegCount* NetFlowModule::get_counts() const
{
    if (netflow_cache && template_cache)
    {
        netflow_stats.netflow_cache_bytes_in_use = netflow_cache->current_size;
        netflow_stats.template_cache_bytes_in_use = template_cache->current_size;
    }
    else
    {
        netflow_stats.netflow_cache_bytes_in_use = 0;
        netflow_stats.template_cache_bytes_in_use = 0;
    }
    return (PegCount*)&netflow_stats;
}

const PegInfo* NetFlowModule::get_pegs() const
{ return netflow_pegs; }

ProfileStats* NetFlowModule::get_profile() const
{ return &netflow_perf_stats; }
