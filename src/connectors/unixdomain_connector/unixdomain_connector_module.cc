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

// unixdomain_connector_module.cc author Umang Sharma <umasharm@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "unixdomain_connector_module.h"

#include <sstream>
#include <string>

#include "log/messages.h"
#include "main/thread_config.h"

using namespace snort;
using namespace std;

static const Parameter unixdomain_connector_params[] =
{
    { "connector", Parameter::PT_STRING, nullptr, nullptr,
      "connector name" },

    { "paths", Parameter::PT_STR_LIST, nullptr, nullptr,
      "list of paths to remote end-point" },

    { "conn_retries", Parameter::PT_BOOL, nullptr, "false",
      "retries to establish connection enabled or not" },

    { "setup", Parameter::PT_ENUM, "call | answer", nullptr,
      "stream establishment" },

    { "retry_interval", Parameter::PT_INT, "1:50", "4",
      "retry interval in seconds" },

    { "max_retries", Parameter::PT_INT, "1:50", "5",
      "maximum number of retries" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo unixdomain_connector_pegs[] =
{
    { CountType::SUM, "messages", "total messages" },
    { CountType::END, nullptr, nullptr }
};

extern THREAD_LOCAL SimpleStats unixdomain_connector_stats;
extern THREAD_LOCAL ProfileStats unixdomain_connector_perfstats;

//-------------------------------------------------------------------------
// unixdomain_connector module
//-------------------------------------------------------------------------

UnixDomainConnectorModule::UnixDomainConnectorModule() :
    Module(UNIXDOMAIN_CONNECTOR_NAME, UNIXDOMAIN_CONNECTOR_HELP, unixdomain_connector_params, true)
{ }

ProfileStats* UnixDomainConnectorModule::get_profile() const
{ return &unixdomain_connector_perfstats; }

static void fill_paths(vector<string>& paths, const string& s)
{
    string path;
    stringstream ss(s);

    while (ss >> path)
        paths.push_back(path);
}

bool UnixDomainConnectorModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("connector") )
        config->connector_name = v.get_string();

    else if ( v.is("paths") )
        fill_paths(config->paths, v.get_string());

    else if ( v.is("setup") )
    {
        switch ( v.get_uint8() )
        {
        case 0:
            config->setup = UnixDomainConnectorConfig::CALL;
            break;
        case 1:
            config->setup = UnixDomainConnectorConfig::ANSWER;
            break;
        default:
            return false;
        }
    }

    else if ( v.is("conn_retries") )
        config->conn_retries = v.get_bool();
    
    else if ( v.is("retry_interval") )
        config->retry_interval = v.get_uint32();
    
    else if ( v.is("max_retries") )
        config->max_retries = v.get_uint32();

    else
        return false;   

    return true;
}

ConnectorConfig::ConfigSet UnixDomainConnectorModule::get_and_clear_config()
{
    return std::move(config_set);
}

bool UnixDomainConnectorModule::begin(const char*, int, SnortConfig*)
{
    if ( !config )
    {
        config = std::make_unique<UnixDomainConnectorConfig>();
        config->direction = Connector::CONN_DUPLEX;
    }

    return true;
}

bool UnixDomainConnectorModule::end(const char*, int idx, SnortConfig*)
{
    if (idx != 0)
    {
        if ( config->paths.size() > 1 and config->paths.size() < ThreadConfig::get_instance_max() )
        {
            ParseError("The number of paths specified is insufficient to cover all threads. "
                "Number of threads: %d.", ThreadConfig::get_instance_max());
            return false;
        }

        config_set.emplace_back(std::move(config));
    }

    return true;
}

const PegInfo* UnixDomainConnectorModule::get_pegs() const
{ return unixdomain_connector_pegs; }

PegCount* UnixDomainConnectorModule::get_counts() const
{ return (PegCount*)&unixdomain_connector_stats; }

